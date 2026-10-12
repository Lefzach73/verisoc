"""Independent context recomputation: never imports/calls candidate derivation."""

from verisoc.core.errors import VeriSOCError
from verisoc.core.models import Case
from verisoc.evidence.models import FactCandidate
from verisoc.storage.repository import Repository
from verisoc.v05.context_models import (
    ContextBundle,
    ContextCandidate,
    VerifiedContext,
    context_identity,
    verification_capability,
)
from verisoc.v05.context_source import context_rows
from verisoc.verification.facts import verify_fact


def verify_context(
    repo: Repository,
    case: Case,
    fact: FactCandidate,
    candidate: ContextCandidate,
    bundle: ContextBundle,
) -> VerifiedContext | None:
    try:
        repo._scope(case)
        repo._scope(candidate)
        proposal = ContextCandidate.model_validate(
            candidate.model_dump(mode="json", exclude={"verification_status"})
        )
        checked = verify_fact(repo, case, fact).verified_fact
        if checked is None or proposal.fact_id != context_identity(proposal):
            return None
        if (
            proposal.case_id != case.case_id
            or proposal.dataset_id != case.dataset_id
            or proposal.explained_fact_id != checked.fact_id
            or proposal.event_proofs != checked.evidence_hashes
            or proposal.source_id != bundle.authority.source_id
        ):
            return None
        admitted = context_rows(repo, bundle)
        matches = [r for r, p in admitted if p == proposal.source_proof and r == proposal.activity]
        if len(matches) != 1:
            return None
        activity = matches[0]
        if (
            activity.dataset_id != case.dataset_id
            or activity.status != "approved"
            or any(r.ticket_id == activity.ticket_id and r.status == "revoked" for r, _ in admitted)
        ):
            return None
        if activity.kind == "approved_password_reset":
            if checked.predicate not in ("failed_login_burst", "success_after_failures"):
                return None
            codes = {4624, 4625}
        else:
            if checked.predicate != "windows_image_match":
                return None
            codes = {4688}
        bindings = {b.event_id: b.canonical_sha256 for b in activity.bindings}
        # Verify every declared binding, including uncited extras, to reject mixed scopes.
        for event_id, hash_value in bindings.items():
            event = repo.get_event(event_id)
            if (
                not repo.provenance_ok(event)
                or event.canonical_sha256 != hash_value
                or event.dataset_id != case.dataset_id
                or event.host_id != activity.host_id
                or event.user_id != activity.principal_id
                or event.attributes.event_code not in codes
                or event.source_ref.file_sha256 != activity.event_source_sha256
                or not case.start_at <= event.occurred_at <= case.end_at
                or not activity.valid_from <= event.occurred_at <= activity.valid_until
            ):
                return None
        if not set(checked.source_event_ids) <= set(bindings):
            return None
        return VerifiedContext.model_validate(
            proposal.model_dump(mode="json"), context=verification_capability()
        )
    except (ValueError, VeriSOCError):
        return None
