import time

from verisoc.core.ids import stable_id
from verisoc.core.models import CandidateReport, Case, InvestigationReport, evidence_detail
from verisoc.detection.rules import APPROVED_RULES, qualified_signal
from verisoc.ingest.privacy import scrub
from verisoc.storage.repository import Repository
from verisoc.verification.verifier import verify


def assemble(
    repo: Repository,
    case: Case,
    proposal: CandidateReport,
    *,
    provider_id: str = "mock",
    model_id: str = "engineering-smoke-1",
    limits: tuple[str, ...] = (),
    manifest_id: str = "offline-demo",
    tokens_input: int = 0,
    tokens_output: int = 0,
    cost: float = 0,
    duration: float = 0,
    deadline: float | None = None,
) -> InvestigationReport:
    assembly_started = time.monotonic()
    checked = []
    for claim in proposal.claims:
        if deadline is not None and time.monotonic() >= deadline:
            limits += ("verification_deadline",)
            break
        checked.append(verify(repo, case, claim))
    decisions = tuple(checked)
    supported = tuple(
        d.model_copy(
            update={
                "candidate": d.candidate.model_copy(
                    update={"explanation": "Typed predicate satisfied; no inferred intent."}
                )
            }
        )
        for d in decisions
        if d.status == "verified"
    )
    refs = tuple(sorted({e for d in supported for e in d.supporting_event_ids}, key=str))
    # An explicitly unverified interpretation contributes no factual support. It does not
    # invalidate otherwise complete facts. Rejected/foreign/malformed hypotheses still block.
    blocking = tuple(
        d
        for d in decisions
        if d.status != "verified"
        and not (
            d.candidate.claim_kind == "analyst_inference"
            and d.status == "insufficient"
            and d.reason_code == "interpretation_not_provable"
        )
    )
    incomplete = bool(limits or proposal.uncertainties or blocking)
    verdict = "needs_review"
    if (
        not incomplete
        and case.alert
        and case.alert.rule_id in APPROVED_RULES
        and case.alert.severity == "high"
        and set(case.alert.event_ids).issubset(refs)
        and qualified_signal(case, [repo.get_event(e) for e in case.alert.event_ids])
        and proposal.proposed_verdict == "malicious"
    ):
        verdict = "malicious"
    # Absence of an alert cannot establish benignness. Negative cases conservatively abstain.
    missing = {d.reason_code for d in blocking}
    if not supported:
        missing.add("no_verified_observations")
    if proposal.uncertainties:
        missing.add("candidate_uncertainty")
    if case.alert and not set(case.alert.event_ids).issubset(refs):
        missing.add("incomplete_alert_support")
    if verdict == "needs_review" and not missing and not limits:
        missing.add("no_qualified_verdict_signal")
    report = InvestigationReport.model_validate(
        dict(
            report_id=stable_id(
                case.case_id, manifest_id, provider_id, proposal.model_dump_json(), limits
            ),
            case_id=case.case_id,
            tenant_id=repo.tenant,
            verdict=verdict,
            verified_claims=supported,
            hypotheses=tuple(
                d.candidate.model_copy(update={"explanation": scrub(d.candidate.explanation)})
                for d in decisions
                if d.status == "insufficient" and d.candidate.claim_kind == "analyst_inference"
            ),
            missing_evidence=tuple(sorted(missing)),
            limit_reasons=limits,
            evidence_refs=refs,
            evidence_details=tuple(evidence_detail(repo.get_event(e)) for e in refs),
            run_manifest_id=manifest_id,
            provider_id=provider_id,
            model_id=model_id,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            estimated_usd=cost,
            total_duration_ms=duration + (time.monotonic() - assembly_started) * 1000,
        )
    )
    repo.put_report(report)
    return report
