from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, IPvAnyAddress, ValidationInfo, field_validator, model_validator

from verisoc.core.ids import stable_id
from verisoc.core.models import Digest, Frozen, Text, utc

Predicate = Literal[
    "observed_event",
    "failed_login_burst",
    "multi_account_failures",
    "source_account_failures",
    "success_after_failures",
    "windows_image_match",
]


class FactArguments(Frozen):
    event_code: Literal[4624, 4625, 4688, 3] | None = None
    outcome: Literal["success", "failure", "unknown"] | None = None
    host_id: Text | None = None
    user_id: Text | None = None
    process_name: Text | None = None
    src_ip: IPvAnyAddress | None = None
    dst_ip: IPvAnyAddress | None = None
    dst_port: Annotated[int, Field(strict=True, ge=0, le=65535)] | None = None
    start_at: datetime
    end_at: datetime
    event_count: Annotated[int, Field(strict=True, ge=1, le=500)]
    distinct_users: Annotated[int, Field(strict=True, ge=1, le=500)] | None = None

    @field_validator("start_at", "end_at", mode="before")
    @classmethod
    def timestamp_type(cls, value: object) -> object:
        if not isinstance(value, (str, datetime)):
            raise ValueError("Typed aware timestamp required")
        return value

    _time = field_validator("start_at", "end_at")(utc)

    @model_validator(mode="after")
    def ordered(self) -> "FactArguments":
        if self.start_at > self.end_at:
            raise ValueError("Reversed fact interval")
        return self


class EvidenceHash(Frozen):
    event_id: UUID
    canonical_sha256: Digest
    raw_row_sha256: Digest
    file_sha256: Digest
    row_index: Annotated[int, Field(strict=True, ge=1, le=5000)]


class FactCandidate(Frozen):
    schema_version: Literal["facts-1.0"] = "facts-1.0"
    fact_id: UUID
    tenant_id: UUID
    case_id: UUID
    dataset_id: Text
    predicate: Predicate
    arguments: FactArguments
    source_event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=500)]
    derivation_rule_id: Text
    derivation_rule_version: Text
    evidence_hashes: Annotated[tuple[EvidenceHash, ...], Field(min_length=1, max_length=500)]
    input_hash: Digest

    @model_validator(mode="after")
    def source_binding(self) -> "FactCandidate":
        if len(set(self.source_event_ids)) != len(self.source_event_ids):
            raise ValueError("Repeated source event ID")
        if tuple(h.event_id for h in self.evidence_hashes) != self.source_event_ids:
            raise ValueError("Evidence identity/order mismatch")
        return self


def fact_identity(data: dict[str, Any]) -> UUID:
    from verisoc.core.provenance import json_hash

    body = {k: v for k, v in data.items() if k not in ("fact_id", "verification_status")}
    return stable_id("verified-fact", json_hash(body))


_CAPABILITY = object()


def fact_context() -> dict[str, object]:
    return {"fact_verification_capability": _CAPABILITY}


class VerifiedFact(FactCandidate):
    verification_status: Literal["verified"] = "verified"

    @model_validator(mode="before")
    @classmethod
    def trusted_only(cls, value: object, info: ValidationInfo) -> object:
        if not info.context or info.context.get("fact_verification_capability") is not _CAPABILITY:
            raise ValueError("Facts require trusted independent verification")
        return value


class FactCheck(Frozen):
    status: Literal["verified", "rejected"]
    reason_code: Text
    verified_fact: VerifiedFact | None = None
