from uuid import uuid4

from verisoc.core.errors import NotFound
from verisoc.core.models import CandidateClaim, Case, VerifiedClaim, verification_context
from verisoc.storage.repository import Repository
from verisoc.verification.predicates import check

VERIFIER_VERSION = "predicates-1.0"


def verify(repo: Repository, case: Case, claim: CandidateClaim) -> VerifiedClaim:
    repo._scope(case)
    records = []
    status, reason = "insufficient", "empty_evidence"
    if claim.subject_event_ids:
        try:
            for eid in claim.subject_event_ids:
                event = repo.get_event(eid)
                if (
                    event.dataset_id != case.dataset_id
                    or not case.start_at <= event.occurred_at <= case.end_at
                ):
                    status, reason = "rejected", "outside_case_scope"
                    break
                if not repo.provenance_ok(event):
                    status, reason = "rejected", "provenance_mismatch"
                    break
                records.append(event)
            else:
                status, reason = check(claim, records)
        except (NotFound, ValueError):
            status, reason = "rejected", "evidence_unavailable"
    decision = VerifiedClaim.model_validate(
        dict(
            candidate=claim,
            status=status,
            verifier_id=VERIFIER_VERSION,
            supporting_event_ids=claim.subject_event_ids if status == "verified" else (),
            reason_code=reason,
        ),
        context=verification_context(),
    )
    repo.record_audit(
        uuid4(),
        {
            "claim_id": str(claim.claim_id),
            "case_id": str(case.case_id),
            "status": status,
            "reason_code": reason,
            "verifier": VERIFIER_VERSION,
        },
    )
    return decision
