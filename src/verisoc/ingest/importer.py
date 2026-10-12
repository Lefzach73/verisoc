import json
from typing import Any
from uuid import UUID

from verisoc.core.ids import demo_tenant
from verisoc.core.models import ImportManifest, RawEvent, SourceRef
from verisoc.core.provenance import digest, json_hash
from verisoc.ingest.normalize import normalize
from verisoc.storage.repository import DEMO_MODE, Repository

MAX_BYTES = 1048576


def import_jsonl(
    repo: Repository, content: bytes, dataset: str, *, fixture_tenant: str | None = None
) -> ImportManifest:
    if len(content) > MAX_BYTES or len(content.splitlines()) > 5000:
        raise ValueError("Import size exceeded")
    if fixture_tenant and demo_tenant(fixture_tenant) != repo.tenant:
        raise ValueError("Fixture context mismatch")

    def unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result

    file_hash = digest(content)
    normalized = []
    seen: set[str] = set()
    duplicates = 0
    for row_index, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            raise ValueError("Blank JSONL record")
        obj = json.loads(line, object_pairs_hook=unique_fields)
        if not isinstance(obj, dict):
            raise ValueError("Expected event object")
        if fixture_tenant:
            if obj.pop("fixture_tenant", None) != fixture_tenant:
                continue
        raw = RawEvent.model_validate(obj)
        raw_hash = json_hash(raw.model_dump(mode="json"))
        if raw_hash in seen:
            duplicates += 1
            continue
        seen.add(raw_hash)
        ref = SourceRef(file_sha256=file_hash, row_index=row_index, raw_row_sha256=raw_hash)
        normalized.append(normalize(raw, repo.tenant, dataset, ref))
    if not normalized:
        raise ValueError("Empty import")
    repo.pin_dataset(dataset, file_hash)
    ids: list[UUID] = []
    accepted = 0
    for event in normalized:
        accepted += repo.put_event(event)
        ids.append(event.event_id)
    return ImportManifest(
        tenant_id=repo.tenant,
        dataset_id=dataset,
        file_sha256=file_hash,
        accepted=accepted,
        duplicates=duplicates + len(normalized) - accepted,
        event_ids=tuple(ids),
        mode=DEMO_MODE if repo.conn.dialect.name == "sqlite" else "AUTHENTICATED_POSTGRES_RLS",
    )
