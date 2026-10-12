"""Authorization and immutable source-lineage boundary shared by evidence consumers."""

from datetime import timedelta

from verisoc.core.errors import BudgetExceeded, NotFound
from verisoc.core.models import CanonicalEvent, Case
from verisoc.core.provenance import json_hash
from verisoc.evidence.models import EvidenceHash
from verisoc.storage.repository import Repository

MAX_CASE_EVENTS = 500


def read_case_events(repo: Repository, case: Case) -> list[CanonicalEvent]:
    repo._scope(case)
    if case.end_at - case.start_at > timedelta(hours=24):
        raise BudgetExceeded("v04_case_time_limit")
    rows = repo.list_events(
        case.dataset_id,
        start=case.start_at.isoformat(),
        end=case.end_at.isoformat(),
        limit=MAX_CASE_EVENTS + 1,
    )
    if len(rows) > MAX_CASE_EVENTS:
        raise BudgetExceeded("v04_case_event_limit")
    if not rows:
        raise NotFound("Record unavailable")
    if not set(case.event_ids).issubset({e.event_id for e in rows}):
        raise NotFound("Record unavailable")
    for event in rows:
        if not repo.provenance_ok(event):
            raise NotFound("Record unavailable")
    return sorted(rows, key=lambda e: (e.occurred_at, str(e.event_id)))


def proof(event: CanonicalEvent) -> EvidenceHash:
    return EvidenceHash(
        event_id=event.event_id,
        canonical_sha256=event.canonical_sha256,
        raw_row_sha256=event.source_ref.raw_row_sha256,
        file_sha256=event.source_ref.file_sha256,
        row_index=event.source_ref.row_index,
    )


def input_hash(case: Case, rows: list[CanonicalEvent], version: str) -> str:
    return json_hash(
        {
            "tenant_id": str(case.tenant_id),
            "case_id": str(case.case_id),
            "dataset_id": case.dataset_id,
            "start": case.start_at.isoformat(),
            "end": case.end_at.isoformat(),
            "ruleset": version,
            "records": [proof(e).model_dump(mode="json") for e in rows],
        }
    )
