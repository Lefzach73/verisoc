import hashlib
import json
from typing import Any

from verisoc.core.models import CanonicalEvent


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_hash(value: Any) -> str:
    return digest(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    )


def event_hash(event: CanonicalEvent) -> str:
    # Admission time is operational metadata, excluded from deterministic identity.
    return json_hash(event.model_dump(mode="json", exclude={"canonical_sha256", "ingested_at"}))
