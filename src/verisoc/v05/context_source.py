"""Strict source admission shared by producer and verifier, not their derivation logic."""

import json
from typing import Any

from verisoc.core.errors import NotFound
from verisoc.core.ids import stable_id
from verisoc.core.provenance import digest, json_hash
from verisoc.storage.repository import Repository
from verisoc.v05.context_models import ActivityRecord, ContextBundle, ContextProof


def unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate context JSON field")
        result[key] = value
    return result


def context_rows(
    repo: Repository, bundle: ContextBundle
) -> tuple[tuple[ActivityRecord, ContextProof], ...]:
    authority = bundle.authority
    if authority.tenant_id != repo.tenant:
        raise NotFound("Context unavailable")
    if (
        len(bundle.content) > 1048576
        or not bundle.content
        or len(bundle.content.splitlines()) > 1000
    ):
        raise ValueError("Context size exceeded or empty")
    if digest(bundle.content) != authority.file_sha256:
        raise NotFound("Context unavailable")
    result = []
    seen = set()
    for index, line in enumerate(bundle.content.splitlines(), 1):
        record = ActivityRecord.model_validate(json.loads(line, object_pairs_hook=unique_fields))
        if record.dataset_id != authority.dataset_id:
            raise NotFound("Context unavailable")
        row_hash = json_hash(record.model_dump(mode="json"))
        if row_hash in seen:
            continue
        seen.add(row_hash)
        proof = ContextProof(
            file_sha256=authority.file_sha256,
            row_index=index,
            raw_row_sha256=row_hash,
            context_record_id=stable_id(
                "activity",
                repo.tenant,
                authority.dataset_id,
                authority.source_id,
                authority.file_sha256,
                index,
                row_hash,
            ),
        )
        result.append((record, proof))
    return tuple(result)
