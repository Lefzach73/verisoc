"""Case-scoped custodian context, shared by intake, blind review and the study runner."""

import json
from pathlib import Path
from typing import Any
from uuid import UUID

from verisoc.core.provenance import json_hash
from verisoc.evaluation.v05_intake import IntakeCase, IntakeManifest, read_pinned
from verisoc.evaluation.v05_oracle import ContextOracle
from verisoc.evaluation.v05_raw_oracle import SingleTenantOracle
from verisoc.v05.context_models import ActivityRecord, ContextBundle
from verisoc.v05.context_source import unique_fields


class StudyOracle(SingleTenantOracle, ContextOracle):
    """Source-file indexing plus independently implemented context derivation checks."""


def context_bundles(
    root: Path, manifest: IntakeManifest, case: IntakeCase
) -> tuple[ContextBundle, ...]:
    pins = {p.pin_id: p for p in manifest.context_sources}
    files = {f.path: f for f in manifest.files}
    result = []
    for name in case.context_pins:
        pin = pins[name]
        if pin.authority.tenant_id != case.tenant_id or pin.authority.dataset_id != case.dataset_id:
            raise ValueError("Context pin crosses tenant or dataset")
        entry = files[pin.file]
        if entry.role != "context" or entry.sha256 != pin.authority.file_sha256:
            raise ValueError("Context pin/source hash mismatch")
        result.append(ContextBundle(authority=pin.authority, content=read_pinned(root, entry)))
    return tuple(result)


def visible_context(bundle: ContextBundle, event_ids: set[UUID]) -> list[dict[str, Any]]:
    """Never expose records referring to events outside the authorized case."""
    output = []
    seen = set()
    rows = []
    for number, line in enumerate(bundle.content.splitlines(), 1):
        record = ActivityRecord.model_validate(json.loads(line, object_pairs_hook=unique_fields))
        row_hash = json_hash(record.model_dump(mode="json"))
        if row_hash in seen:
            continue
        seen.add(row_hash)
        rows.append((number, record, row_hash))
    visible_tickets = {
        record.ticket_id
        for _, record, _ in rows
        if {b.event_id for b in record.bindings} <= event_ids
    }
    revoked = {record.ticket_id for _, record, _ in rows if record.status == "revoked"}
    for number, record, row_hash in rows:
        if {b.event_id for b in record.bindings} <= event_ids:
            output.append(
                dict(
                    source_id=bundle.authority.source_id,
                    source_file_sha256=bundle.authority.file_sha256,
                    source_row=number,
                    raw_row_sha256=row_hash,
                    record=record.model_dump(mode="json"),
                    effective_status="revoked" if record.ticket_id in revoked else record.status,
                    status="source_assertion_not_a_verified_incident_verdict",
                )
            )
        elif record.status == "revoked" and record.ticket_id in visible_tickets:
            # Runtime revocation is ticket-wide. Expose that disposition without another
            # case's event IDs, identities or activity details.
            output.append(
                dict(
                    source_id=bundle.authority.source_id,
                    source_file_sha256=bundle.authority.file_sha256,
                    source_row=number,
                    raw_row_sha256=row_hash,
                    revocation_notice=dict(
                        ticket_id=record.ticket_id, status="revoked", foreign_bindings_withheld=True
                    ),
                    status="source_assertion_not_a_verified_incident_verdict",
                )
            )
    return output


def validate_context_inputs(root: Path, manifest: IntakeManifest) -> None:
    pins = {p.pin_id: p for p in manifest.context_sources}
    if len(pins) != len(manifest.context_sources):
        raise ValueError("Duplicate context pin")
    declared = {f.path for f in manifest.files if f.role == "context"}
    if declared != {p.file for p in manifest.context_sources}:
        raise ValueError("Every context file requires an explicit authority pin")
    used = {name for c in manifest.cases for name in c.context_pins}
    if used != set(pins):
        raise ValueError("Unknown or unused context authority pin")
    files = {f.path: f for f in manifest.files}
    for case in manifest.cases:
        if len(set(case.context_pins)) != len(case.context_pins):
            raise ValueError("Duplicate case context pin")
        bundles = context_bundles(root, manifest, case)
        if len({b.authority.source_id for b in bundles}) != len(bundles):
            raise ValueError("One snapshot per context authority is required")
        oracle = StudyOracle(
            read_pinned(root, files[case.event_file]), case.tenant_id, case.dataset_id
        )
        for bundle in bundles:
            if len(bundle.content.splitlines()) > 1000:
                raise ValueError("Context row limit exceeded")
            for line in bundle.content.splitlines():
                record = ActivityRecord.model_validate(
                    json.loads(line, object_pairs_hook=unique_fields)
                )
                if record.dataset_id != case.dataset_id or any(
                    b.event_id not in oracle.records for b in record.bindings
                ):
                    raise ValueError("Context references foreign or unavailable source records")
