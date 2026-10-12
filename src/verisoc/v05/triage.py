"""Separate evidence correctness, context explanation, triage and incident intent."""

from typing import Literal
from uuid import UUID

from verisoc.core.errors import VeriSOCError
from verisoc.core.models import Case, Frozen
from verisoc.evidence.registry import EvidenceRegistry
from verisoc.investigation.evidence_pipeline import FactView, view
from verisoc.storage.repository import Repository
from verisoc.v05.context_derive import propose_context
from verisoc.v05.context_models import ContextBundle, VerifiedContext
from verisoc.v05.context_verify import verify_context
from verisoc.verification.facts import verify_facts


class TriageReport(Frozen):
    pipeline: Literal["B3-hybrid-v0.5"] = "B3-hybrid-v0.5"
    case_id: UUID
    tenant_id: UUID
    verified_observations: tuple[FactView, ...] = ()
    indicator_evidence: tuple[FactView, ...] = ()
    verified_context: tuple[VerifiedContext, ...] = ()
    unexplained_indicator_ids: tuple[UUID, ...] = ()
    selected_fact_ids: tuple[UUID, ...] = ()
    omitted_indicator_ids: tuple[UUID, ...] = ()
    triage_flag: bool = False
    disposition: Literal["suspicious", "explained_activity", "observation_only", "review_required"]
    incident_verdict: Literal["needs_review"] = "needs_review"
    reason_codes: tuple[str, ...] = ()
    missing_fields: tuple[str, ...] = ()
    limitation: str = (
        "Recorded authorization is context, not proof of benign intent or source truth."
    )


def triage(
    repo: Repository,
    case: Case,
    bundles: tuple[ContextBundle, ...] = (),
    *,
    selected_fact_ids: tuple[UUID, ...] | None = None,
) -> TriageReport:
    repo._scope(case)
    if len({b.authority.source_id for b in bundles}) != len(bundles):
        raise ValueError("Only one pinned snapshot per context authority is allowed")
    if len(bundles) > 8:
        raise ValueError("Context source budget exceeded")
    try:
        registry = EvidenceRegistry(repo, case)
    except (ValueError, VeriSOCError):
        return TriageReport(
            case_id=case.case_id,
            tenant_id=repo.tenant,
            disposition="review_required",
            reason_codes=("source_unavailable",),
        )
    indicators = [f for f in registry.facts.values() if f.predicate != "observed_event"]
    if selected_fact_ids is not None and (
        len(selected_fact_ids) > 32
        or len(set(selected_fact_ids)) != len(selected_fact_ids)
        or not set(selected_fact_ids) <= set(registry.facts)
    ):
        return TriageReport(
            case_id=case.case_id,
            tenant_id=repo.tenant,
            disposition="review_required",
            reason_codes=("invalid_fact_selection",),
        )
    selected = set(registry.facts) if selected_fact_ids is None else set(selected_fact_ids)
    omitted = tuple(f.fact_id for f in indicators if f.fact_id not in selected)
    explanations = []
    explained = set()
    reasons = []
    for fact in indicators:
        for bundle in bundles:
            try:
                proposals = propose_context(repo, case, fact, bundle)
                for candidate in proposals:
                    result = verify_context(repo, case, fact, candidate, bundle)
                    if result is not None:
                        explanations.append(result)
                        explained.add(fact.fact_id)
                    else:
                        reasons.append("context_verifier_rejected")
            except (ValueError, VeriSOCError):
                reasons.append("context_unavailable")
    # A fresh whole-case recheck detects changes between derivation and policy output.
    final = verify_facts(repo, case, tuple(registry.facts.values()))
    if any(r.verified_fact is None for r in final) or registry.rejections:
        return TriageReport(
            case_id=case.case_id,
            tenant_id=repo.tenant,
            disposition="review_required",
            reason_codes=("verifier_rejected",),
        )
    unexplained = tuple(
        f.fact_id for f in indicators if f.fact_id not in explained and f.fact_id in selected
    )
    disposition: Literal["suspicious", "explained_activity", "observation_only", "review_required"]
    if unexplained:
        disposition = "suspicious"
        reasons.append("unexplained_verified_indicator")
    elif omitted:
        disposition = "review_required"
        reasons.append("indicator_not_selected")
    elif indicators:
        disposition = "explained_activity"
        reasons.append("all_indicator_sources_have_scoped_approval_records")
    else:
        disposition = "observation_only"
        reasons.append("no_signal")
    return TriageReport(
        case_id=case.case_id,
        tenant_id=repo.tenant,
        verified_observations=tuple(
            view(f) for f in registry.facts.values() if f.predicate == "observed_event"
        )[:32],
        indicator_evidence=tuple(view(f) for f in indicators),
        verified_context=tuple(explanations),
        unexplained_indicator_ids=unexplained,
        selected_fact_ids=tuple(sorted(selected, key=str)),
        omitted_indicator_ids=omitted,
        triage_flag=bool(unexplained),
        disposition=disposition,
        reason_codes=tuple(dict.fromkeys(reasons)),
        missing_fields=(
            ("source_grounded_scoped_authorization", "independent_incident_adjudication")
            if unexplained
            else ("independent_incident_adjudication",)
        ),
    )
