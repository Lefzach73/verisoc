"""Custodian-only intake, outside every runtime investigation/provider import path."""

import json
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field

from verisoc.core.ids import stable_id
from verisoc.core.models import Digest, Frozen, RawEvent, Text
from verisoc.core.provenance import digest, json_hash
from verisoc.ingest.privacy import scrub
from verisoc.v05.context_models import ContextAuthority
from verisoc.v05.context_source import unique_fields


class InputFile(Frozen):
    path: Text
    sha256: Digest
    role: Literal["events", "permission", "power_analysis", "preregistration", "context"]


class ContextInput(Frozen):
    pin_id: Text
    file: Text
    authority: ContextAuthority


class IntakeCase(Frozen):
    case_id: Text
    family_id: Text
    origin_incident_id: Text
    author_id: Text
    tenant_id: UUID
    dataset_id: Text
    event_file: Text
    row_indexes: Annotated[
        tuple[Annotated[int, Field(strict=True, ge=1, le=5000)], ...],
        Field(min_length=1, max_length=500),
    ]
    partition: Literal["development", "calibration", "holdout"]
    context_pins: Annotated[tuple[Text, ...], Field(max_length=8)] = ()


class IntakeManifest(Frozen):
    schema_version: Literal["intake-1.0", "intake-1.1"] = "intake-1.1"
    study_id: Annotated[str, Field(pattern=r"^[a-z0-9-]{1,64}$")]
    provenance: Literal["synthetic_development", "external_independent_candidate"]
    custodian_id: Text
    license_id: Text
    privacy_attestation: Text
    permission_file: Text
    files: Annotated[tuple[InputFile, ...], Field(min_length=2, max_length=600)]
    cases: Annotated[tuple[IntakeCase, ...], Field(min_length=1, max_length=500)]
    context_sources: Annotated[tuple[ContextInput, ...], Field(max_length=500)] = ()


class ContaminationIndex(Frozen):
    schema_version: Literal["contamination-1.0"] = "contamination-1.0"
    case_ids: tuple[str, ...]
    origin_ids: tuple[str, ...]
    family_ids: tuple[str, ...]
    signatures: tuple[str, ...]
    source_hashes: tuple[str, ...]


def pinned_path(root: Path, entry: InputFile) -> Path:
    relative = PurePosixPath(entry.path)
    path = root / entry.path
    if relative.is_absolute() or ".." in relative.parts or path.is_symlink():
        raise ValueError("Unsafe intake path")
    if not path.resolve().is_relative_to(root.resolve()) or path.stat().st_size > 1048576:
        raise ValueError("Intake path escape or excessive size")
    return path


def read_pinned(root: Path, entry: InputFile) -> bytes:
    content = pinned_path(root, entry).read_bytes()
    if not content or digest(content) != entry.sha256:
        raise ValueError("Missing source or intake hash mismatch")
    return content


def read_events(content: bytes) -> list[RawEvent]:
    if len(content.splitlines()) > 5000:
        raise ValueError("Event row limit exceeded")
    result = []
    for line in content.splitlines():
        obj = json.loads(line, object_pairs_hook=unique_fields)
        result.append(RawEvent.model_validate(obj))
    return result


def relative_signature(records: list[dict[str, Any]]) -> str:
    """Detect common time/entity-renamed siblings; not a complete graph-isomorphism proof."""
    if not records:
        raise ValueError("Nonempty records required")
    normalized = []
    aliases: dict[str, dict[str, int]] = {}
    ordered = sorted(
        records,
        key=lambda r: (
            r["timestamp"],
            r["event_code"],
            r.get("process") or "",
            r.get("dst_port") or 0,
        ),
    )
    start = min(datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00")) for r in ordered)
    for record in ordered:
        row = {
            k: v for k, v in record.items() if k not in ("timestamp", "fixture_tenant", "message")
        }
        for field in ("host", "user", "src_ip", "dst_ip"):
            value = row.get(field)
            if value is not None:
                group = aliases.setdefault(field, {})
                row[field] = group.setdefault(str(value), len(group))
        row["relative_seconds"] = (
            datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")) - start
        ).total_seconds()
        normalized.append(row)
    return json_hash(sorted(normalized, key=lambda r: json.dumps(r, sort_keys=True)))


def validate_intake(
    root: Path, manifest: IntakeManifest, contamination: ContaminationIndex
) -> dict[str, Any]:
    files = {f.path: f for f in manifest.files}
    cases = {c.case_id: c for c in manifest.cases}
    if len(files) != len(manifest.files) or len(cases) != len(manifest.cases):
        raise ValueError("Duplicate file/case identifier")
    if (
        manifest.permission_file not in files
        or files[manifest.permission_file].role != "permission"
    ):
        raise ValueError("Permission evidence is required")
    if sum(pinned_path(root, entry).stat().st_size for entry in files.values()) > 16 * 1048576:
        raise ValueError("Intake batch exceeds 16 MiB")
    content = {name: read_pinned(root, entry) for name, entry in files.items()}
    if len(content[manifest.permission_file].strip()) < 20:
        raise ValueError("Permission record is empty or incomplete")
    events = {
        name: read_events(data) for name, data in content.items() if files[name].role == "events"
    }
    signatures: dict[str, set[str]] = {}
    family_partitions: dict[str, set[str]] = {}
    origin_partitions: dict[str, set[str]] = {}
    case_details = []
    dataset_sources: dict[tuple[UUID, str], str] = {}
    observation_cases: dict[str, list[tuple[str, str]]] = {}
    for case in manifest.cases:
        if case.event_file not in events:
            raise ValueError("Case references unavailable event file")
        if len(set(case.row_indexes)) != len(case.row_indexes) or any(
            type(i) is not int or not 1 <= i <= len(events[case.event_file])
            for i in case.row_indexes
        ):
            raise ValueError("Invalid/repeated source row")
        scope_key = (case.tenant_id, case.dataset_id)
        file_hash = files[case.event_file].sha256
        if scope_key in dataset_sources and dataset_sources[scope_key] != file_hash:
            raise ValueError("Dataset identity cannot bind conflicting source files")
        dataset_sources[scope_key] = file_hash
        source_events = events[case.event_file]
        first_rows: dict[str, int] = {}
        for index, event in enumerate(source_events, 1):
            first_rows.setdefault(json_hash(event.model_dump(mode="json")), index)
        selected = [source_events[i - 1] for i in case.row_indexes]
        start, end = min(r.timestamp for r in selected), max(r.timestamp for r in selected)
        exact_rows = {
            index
            for index, event in enumerate(source_events, 1)
            if start <= event.timestamp <= end
            and first_rows[json_hash(event.model_dump(mode="json"))] == index
        }
        if set(case.row_indexes) != exact_rows:
            raise ValueError("Case must include the complete deduplicated evidence window")
        hashes = [json_hash(r.model_dump(mode="json")) for r in selected]
        if len(set(hashes)) != len(hashes):
            raise ValueError("Duplicate source content cannot count as separate evidence")
        for raw_hash in hashes:
            previous = observation_cases.setdefault(raw_hash, [])
            if any(partition != case.partition for _, partition in previous):
                raise ValueError("Shared source observations overlap evaluation partitions")
            if previous and case.partition == "holdout":
                raise ValueError(
                    "Shared source observations cannot count as separate holdout cases"
                )
            previous.append((case.case_id, case.partition))
        if (
            max(r.timestamp for r in selected) - min(r.timestamp for r in selected)
        ).total_seconds() > 86400:
            raise ValueError("Case exceeds 24-hour runtime contract")
        if any(scrub(r.message) != r.message for r in selected):
            raise ValueError("Source needs privacy scrubbing before intake")
        signature = relative_signature([r.model_dump(mode="json") for r in selected])
        tainted = (
            case.case_id in contamination.case_ids
            or case.origin_incident_id in contamination.origin_ids
            or case.family_id in contamination.family_ids
            or signature in contamination.signatures
            or files[case.event_file].sha256 in contamination.source_hashes
        )
        if tainted and case.partition != "development":
            raise ValueError("Historical/inspected cases and siblings may be DEV only")
        if manifest.provenance == "synthetic_development" and case.partition != "development":
            raise ValueError("Authored software controls are development only")
        signatures.setdefault(signature, set()).add(case.partition)
        family_partitions.setdefault(case.family_id, set()).add(case.partition)
        origin_partitions.setdefault(case.origin_incident_id, set()).add(case.partition)
        identifiers = [
            str(stable_id(case.tenant_id, case.dataset_id, files[case.event_file].sha256, i, h))
            for i, h in zip(case.row_indexes, hashes, strict=True)
        ]
        case_details.append(
            dict(
                case_id=case.case_id,
                family_id=case.family_id,
                partition=case.partition,
                event_ids=identifiers,
                source_rows=list(case.row_indexes),
                relative_signature=signature,
                contaminated=tainted,
                source_sha256=files[case.event_file].sha256,
            )
        )
    if any(
        len(parts) > 1
        for groups in (signatures, family_partitions, origin_partitions)
        for parts in groups.values()
    ):
        raise ValueError("Content/family/origin overlap across partitions")
    from verisoc.evaluation.v05_context_inputs import validate_context_inputs

    validate_context_inputs(root, manifest)
    held = [c for c in manifest.cases if c.partition == "holdout"]
    held_details = [c for c in case_details if c["partition"] == "holdout"]
    if len({c["relative_signature"] for c in held_details}) != len(held_details):
        raise ValueError("Repeated holdout observation pattern needs independent custodian audit")
    if len({c.origin_incident_id for c in held}) != len(held):
        raise ValueError("An incident origin cannot count as multiple holdout incidents")
    blockers = [
        "custodian must verify human identities, blinding, permission and independence",
        "two submitted blinded reviews and adjudication are not supplied by intake",
        "study-specific paid model authorization is absent",
    ]
    if len(held) < 200:
        blockers.append("fewer than 200 independent holdout incidents")
    if len({c.family_id for c in held}) < 20:
        blockers.append("fewer than 20 holdout families")
    if not any(f.role == "power_analysis" for f in manifest.files):
        blockers.append("custodian power analysis absent")
    if not any(f.role == "preregistration" for f in manifest.files):
        blockers.append("external preregistration absent")
    return dict(
        structural_status="PASS",
        scientific_status="BLOCKED",
        blockers=blockers,
        independent_human_review_verified=False,
        cases=case_details,
        manifest_sha256=json_hash(manifest.model_dump(mode="json")),
        file_sha256={name: entry.sha256 for name, entry in files.items()},
        limitation="Fingerprint screening cannot certify custody, independence or permission.",
    )
