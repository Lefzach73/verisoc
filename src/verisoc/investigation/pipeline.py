import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from verisoc.core.errors import BudgetExceeded, ProviderFailure, VeriSOCError
from verisoc.core.models import CandidateReport, Case, InvestigationReport
from verisoc.investigation.prompts import claim_limit, messages
from verisoc.investigation.tool_router import ToolRouter, project
from verisoc.llm.base import Budget, Provider
from verisoc.llm.validation import parse_candidate
from verisoc.reporting.assemble import assemble
from verisoc.storage.repository import Repository


@dataclass
class Attempt:
    proposal: CandidateReport = field(
        default_factory=lambda: CandidateReport(claims=(), proposed_verdict="needs_review")
    )
    tokens_input: int = 0
    tokens_output: int = 0
    estimated_usd: float = 0
    duration_ms: float = 0
    limits: tuple[str, ...] = ()
    tool_trace: list[dict[str, Any]] = field(default_factory=list)
    raw_outputs: list[str] = field(default_factory=list)
    context: list[dict[str, Any]] = field(default_factory=list)
    provider_calls: list[dict[str, Any]] = field(default_factory=list)


async def candidate(
    repo: Repository,
    case: Case,
    provider: Provider,
    budget: Budget,
    *,
    retrieval: bool = True,
    selection: bool = True,
    seed: int = 20261011,
) -> Attempt:
    if not retrieval:
        budget = budget.model_copy(update={"max_tool_calls": 0})
    result = Attempt()
    started = time.monotonic()
    router = ToolRouter(repo, case, max_calls=budget.max_tool_calls)
    history: list[dict[str, Any]] = []
    try:
        # B1 gets fixed alert evidence only. B2/B3 get same bounded read-only retrieval.
        ids = case.alert.event_ids if case.alert else case.event_ids[:1]
        if retrieval:
            rows = router.execute(
                "search_events",
                {
                    "case_id": str(case.case_id),
                    "start": case.start_at.isoformat(),
                    "end": case.end_at.isoformat(),
                    "limit": 64,
                },
            )
            if selection:
                # Fetch the signal itself even when it lies beyond the first search page.
                # Both B2 and B3 pay for the same bounded authorized tool opportunity.
                witnesses = router.execute(
                    "get_evidence", {"event_ids": [str(e) for e in ids[:64]]}
                )
                unique = {row["event_id"]: row for row in witnesses + rows}
                ids_set = set(map(str, ids))
                rows = sorted(
                    unique.values(),
                    key=lambda row: (
                        row["event_id"] not in ids_set,
                        row["occurred_at"],
                        row["event_id"],
                    ),
                )
            # A native dense witness has up to 33 records. Never truncate its final success.
            selected_limit = min(64, max(32, len(ids))) if selection else 64
            result.context = rows[:selected_limit]
        else:
            result.context = [project(router.event(e)) for e in ids[:32]]
        history = messages(case, result.context)
        remaining_output = budget.max_output_tokens
        for _ in range(budget.max_model_calls):
            payload_bytes = provider.input_upper_bound(history, budget, seed)
            if payload_bytes + result.tokens_input > budget.max_input_tokens:
                raise BudgetExceeded("input_tokens_preflight")
            # UTF-8 bytes are a conservative input token upper bound for supported adapters.
            reserved = (
                payload_bytes * provider.input_usd_per_million
                + remaining_output * provider.output_usd_per_million
            ) / 1_000_000
            if reserved + result.estimated_usd > budget.max_usd:
                raise BudgetExceeded("cost_preflight")
            remaining = budget.max_seconds - (time.monotonic() - started)
            if remaining <= 0 or remaining_output <= 0:
                raise BudgetExceeded("deadline_or_output_budget")
            call_budget = budget.model_copy(
                update={"max_seconds": remaining, "max_output_tokens": remaining_output}
            )
            reply = await asyncio.wait_for(
                provider.generate(history, call_budget, seed), timeout=remaining
            )
            result.tokens_input += reply.tokens_input
            result.tokens_output += reply.tokens_output
            call_cost = (
                reply.cost_usd
                if reply.cost_usd is not None
                else (
                    reply.tokens_input * provider.input_usd_per_million
                    + reply.tokens_output * provider.output_usd_per_million
                )
                / 1_000_000
            )
            result.estimated_usd += call_cost
            result.provider_calls.append(
                {
                    "completion_id": reply.completion_id,
                    "provider": reply.backend_provider,
                    "model": reply.provider_model,
                    "finish_reason": reply.finish_reason,
                    "tokens_input": reply.tokens_input,
                    "tokens_output": reply.tokens_output,
                    "usd": call_cost,
                    "cost_basis": "provider_reported"
                    if reply.cost_usd is not None
                    else "token_estimate",
                }
            )
            remaining_output -= reply.tokens_output
            if (
                result.tokens_input > budget.max_input_tokens
                or remaining_output < 0
                or result.estimated_usd > budget.max_usd
            ):
                raise BudgetExceeded("provider_usage_exceeded")
            if len(reply.content.encode()) > budget.max_response_bytes:
                raise BudgetExceeded("output_bytes")
            # Raw outputs are retained only by the separate synthetic evaluation harness.
            result.raw_outputs.append(
                reply.raw_output if reply.raw_output is not None else reply.content
            )
            if reply.error_code:
                raise ProviderFailure(reply.error_code)
            if reply.finish_reason == "length":
                raise ProviderFailure("output_truncated")
            if reply.tool_calls:
                if not retrieval:
                    raise ProviderFailure("tools_disabled")
                history.append(
                    {
                        "role": "assistant",
                        "content": reply.content or None,
                        "tool_calls": [
                            {
                                "id": c.call_id,
                                "type": "function",
                                "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                            }
                            for c in reply.tool_calls
                        ],
                    }
                )
                for call in reply.tool_calls:
                    answer = router.execute(call.name, call.arguments)
                    if call.name == "submit_candidate_report":
                        proposal = CandidateReport.model_validate(answer)
                        if len(proposal.claims) > claim_limit(case):
                            raise BudgetExceeded("claim_count_budget")
                        result.proposal = proposal
                        return result
                    history.append(
                        {
                            "role": "tool",
                            "tool_call_id": call.call_id,
                            "content": json.dumps(answer, sort_keys=True),
                        }
                    )
            else:
                proposal = parse_candidate(reply.content, budget.max_response_bytes)
                if len(proposal.claims) > claim_limit(case):
                    raise BudgetExceeded("claim_count_budget")
                result.proposal = proposal
                return result
        raise BudgetExceeded("model_call_budget")
    except TimeoutError:
        result.limits = ("provider_timeout",)
    except BudgetExceeded as exc:
        result.limits = (str(exc),)
    except ProviderFailure as exc:
        result.limits = (str(exc),)
    except (VeriSOCError, ValidationError, ValueError, RecursionError):
        result.limits = ("invalid_candidate_or_tool",)
    finally:
        result.duration_ms = (time.monotonic() - started) * 1000
        result.tool_trace = router.trace
    return result


def investigate(
    repo: Repository,
    case: Case,
    provider: Provider,
    budget: Budget,
    *,
    manifest_id: str = "offline-demo",
) -> InvestigationReport:
    started = time.monotonic()
    attempt = asyncio.run(candidate(repo, case, provider, budget))
    return assemble(
        repo,
        case,
        attempt.proposal,
        provider_id=provider.provider_id,
        model_id=provider.model_id,
        limits=attempt.limits,
        manifest_id=manifest_id,
        tokens_input=attempt.tokens_input,
        tokens_output=attempt.tokens_output,
        cost=attempt.estimated_usd,
        duration=attempt.duration_ms,
        deadline=started + budget.max_seconds,
    )
