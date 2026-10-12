"""Comparators are confined to local evaluation artifacts, never vetted API reports."""

import asyncio
import time
from copy import deepcopy
from dataclasses import dataclass

from verisoc.core.models import CandidateReport, Case, InvestigationReport, VerifiedClaim
from verisoc.investigation.pipeline import Attempt, candidate
from verisoc.llm.base import Budget, Provider
from verisoc.llm.mock import observed
from verisoc.reporting.assemble import assemble
from verisoc.storage.repository import Repository
from verisoc.verification.verifier import verify

ARMS = {"B0", "B1", "B2", "B3"}
ABLATIONS = {"minus-verifier", "minus-evidence-selection", "minus-abstention", "minus-correlation"}


@dataclass
class Prediction:
    attempt: Attempt
    verdict: str
    emitted: tuple[VerifiedClaim, ...]
    decisions: tuple[VerifiedClaim, ...]
    report: InvestigationReport | None
    gated: bool


def run_arm(
    repo: Repository,
    case: Case,
    provider: Provider,
    budget: Budget,
    arm: str,
    manifest: str,
    seed: int,
    ablation: str | None = None,
    replay: Attempt | None = None,
) -> Prediction:
    started = time.monotonic()
    if arm not in ARMS or (ablation and (arm != "B3" or ablation not in ABLATIONS)):
        raise ValueError("Invalid arm/ablation")
    if replay is not None and (
        arm not in ("B2", "B3") or ablation in ("minus-evidence-selection", "minus-correlation")
    ):
        raise ValueError("Replay requires identical evidence opportunity")
    if replay is not None:
        attempt = deepcopy(replay)
    elif arm == "B0":
        ids = case.alert.event_ids if case.alert else case.event_ids[:1]
        proposal = CandidateReport(
            claims=tuple(observed(repo.get_event(e)) for e in ids[:32]),
            proposed_verdict="malicious"
            if case.alert and case.alert.severity == "high"
            else "needs_review"
            if case.alert
            else "benign",
        )
        attempt = Attempt(proposal=proposal, duration_ms=(time.monotonic() - started) * 1000)
    else:
        attempt = asyncio.run(
            candidate(
                repo,
                case,
                provider,
                budget,
                retrieval=arm != "B1",
                selection=ablation != "minus-evidence-selection",
                seed=seed,
            )
        )
    decisions = tuple(verify(repo, case, c) for c in attempt.proposal.claims)
    gated = arm == "B3" and ablation != "minus-verifier"
    report = None
    if gated:
        report = assemble(
            repo,
            case,
            attempt.proposal,
            provider_id=provider.provider_id,
            model_id=provider.model_id,
            limits=attempt.limits,
            manifest_id=manifest,
            tokens_input=attempt.tokens_input,
            tokens_output=attempt.tokens_output,
            cost=attempt.estimated_usd,
            duration=attempt.duration_ms,
        )
        emitted = report.verified_claims
        verdict = report.verdict
        if ablation == "minus-abstention" and not attempt.limits:
            verdict = (
                attempt.proposal.proposed_verdict
            )  # Local comparator, never publish this as vetted.
    else:
        emitted = tuple(d for d in decisions if d.candidate.claim_kind != "analyst_inference")
        verdict = attempt.proposal.proposed_verdict if not attempt.limits else "needs_review"
    if report is not None:
        attempt.duration_ms = report.total_duration_ms
    return Prediction(attempt, verdict, emitted, decisions, report, gated)
