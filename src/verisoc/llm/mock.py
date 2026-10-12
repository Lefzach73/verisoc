"""Engineering smoke only; intentional unsupported candidate exercises verification."""

import json
from typing import Any
from uuid import UUID

from verisoc.core.ids import stable_id
from verisoc.core.models import CandidateClaim, CandidateReport, CanonicalEvent, Case, PredicateArgs
from verisoc.llm.base import Budget, ProviderReply


def observed(event: CanonicalEvent) -> CandidateClaim:
    kind = {
        ("windows_auth", "failure"): "observed_login_failure",
        ("windows_auth", "success"): "observed_login_success",
        ("windows_process", "success"): "observed_process",
        ("network_flow", "success"): "observed_network_connection",
    }[(event.source_kind, event.outcome)]
    return CandidateClaim.model_validate(
        dict(
            claim_id=stable_id(event.event_id, kind),
            claim_kind=kind,
            subject_event_ids=(event.event_id,),
            parameters=PredicateArgs(),
            explanation="Synthetic smoke observation",
        )
    )


def propose(case: Case, events: list[CanonicalEvent]) -> CandidateReport:
    if not events:
        return CandidateReport(claims=(), proposed_verdict="needs_review")
    good = observed(events[0])
    wrong = CandidateClaim(
        claim_id=stable_id(case.case_id, "fabricated"),
        claim_kind="observed_process",
        subject_event_ids=(events[0].event_id,),
        parameters=PredicateArgs(process_name="invented-malware.exe"),
        explanation="Untrusted deliberately fabricated smoke claim",
    )
    return CandidateReport(claims=(good, wrong), proposed_verdict="malicious")


class MockProvider:
    provider_id = "mock"
    model_id = "engineering-smoke-1"
    input_usd_per_million = 0.0
    output_usd_per_million = 0.0
    price_snapshot = "zero-billing-smoke"

    def input_upper_bound(self, messages: list[dict[str, Any]], budget: Budget, seed: int) -> int:
        return len(json.dumps(messages, ensure_ascii=False).encode())

    async def generate(
        self, messages: list[dict[str, Any]], budget: Budget, seed: int
    ) -> ProviderReply:
        obj = json.loads(messages[1]["content"])
        records = obj["events"]
        if not records:
            proposal = CandidateReport(claims=(), proposed_verdict="needs_review")
        else:
            row = records[0]
            kind = {
                ("windows_auth", "failure"): "observed_login_failure",
                ("windows_auth", "success"): "observed_login_success",
                ("windows_process", "success"): "observed_process",
                ("network_flow", "success"): "observed_network_connection",
            }[(row["source_kind"], row["outcome"])]
            claim = CandidateClaim.model_validate(
                dict(
                    claim_id=stable_id(row["event_id"], kind),
                    claim_kind=kind,
                    subject_event_ids=[row["event_id"]],
                )
            )
            wrong = CandidateClaim(
                claim_id=stable_id(obj["case"]["case_id"], "fabricated"),
                claim_kind="observed_process",
                subject_event_ids=(UUID(row["event_id"]),),
                parameters=PredicateArgs(process_name="invented-malware.exe"),
                explanation="Fabricated engineering test claim",
            )
            proposal = CandidateReport(claims=(claim, wrong), proposed_verdict="malicious")
        content = proposal.model_dump_json()
        # Engineering token counts are conservative byte counts, not LLM tokenization claims.
        return ProviderReply(
            content=content,
            tokens_input=len(json.dumps(messages).encode()),
            tokens_output=len(content.encode()),
        )
