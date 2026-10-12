"""Propose narrowly scoped explanations. Every proposal must pass a separate verifier."""

from uuid import UUID

from verisoc.core.models import Case
from verisoc.evidence.models import VerifiedFact
from verisoc.storage.repository import Repository
from verisoc.v05.context_models import ContextBundle, ContextCandidate, context_identity
from verisoc.v05.context_source import context_rows


def propose_context(
    repo: Repository, case: Case, fact: VerifiedFact, bundle: ContextBundle
) -> tuple[ContextCandidate, ...]:
    repo._scope(case)
    repo._scope(fact)
    if fact.case_id != case.case_id or fact.predicate == "observed_event":
        return ()
    result = []
    admitted = context_rows(repo, bundle)
    revoked = {r.ticket_id for r, _ in admitted if r.status == "revoked"}
    for record, proof in admitted:
        if record.status != "approved" or record.ticket_id in revoked:
            continue
        allowed = (
            ("failed_login_burst", "success_after_failures")
            if (record.kind == "approved_password_reset")
            else ("windows_image_match",)
        )
        if fact.predicate not in allowed or record.dataset_id != case.dataset_id:
            continue
        if fact.arguments.host_id != record.host_id:
            continue
        bindings = {b.event_id: b.canonical_sha256 for b in record.bindings}
        records = [repo.get_event(eid) for eid in fact.source_event_ids]
        if any(
            e.user_id != record.principal_id
            or e.host_id != record.host_id
            or e.dataset_id != record.dataset_id
            or e.source_ref.file_sha256 != record.event_source_sha256
            or bindings.get(e.event_id) != e.canonical_sha256
            or not record.valid_from <= e.occurred_at <= record.valid_until
            for e in records
        ):
            continue
        candidate = ContextCandidate(
            fact_id=UUID(int=0),
            tenant_id=repo.tenant,
            case_id=case.case_id,
            dataset_id=case.dataset_id,
            explained_fact_id=fact.fact_id,
            source_id=bundle.authority.source_id,
            activity=record,
            source_proof=proof,
            event_proofs=fact.evidence_hashes,
        )
        result.append(candidate.model_copy(update={"fact_id": context_identity(candidate)}))
    return tuple(result)
