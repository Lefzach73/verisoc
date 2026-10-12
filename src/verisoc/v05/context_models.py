"""Typed authorization observations; a hash is never an authenticity certificate."""

from datetime import datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, ValidationInfo, field_validator, model_validator

from verisoc.core.ids import stable_id
from verisoc.core.models import Digest, Frozen, Text, utc
from verisoc.core.provenance import json_hash
from verisoc.evidence.models import EvidenceHash


class EventBinding(Frozen):
    event_id: UUID
    canonical_sha256: Digest


class ActivityRecord(Frozen):
    schema_version: Literal["activity-1.0"] = "activity-1.0"
    kind: Literal["approved_password_reset", "approved_lab_execution"]
    status: Literal["approved", "revoked"]
    ticket_id: Text
    dataset_id: Text
    event_source_sha256: Digest
    host_id: Text
    principal_id: Text
    approved_at: datetime
    valid_from: datetime
    valid_until: datetime
    bindings: Annotated[tuple[EventBinding, ...], Field(min_length=1, max_length=500)]

    @field_validator("approved_at", "valid_from", "valid_until", mode="before")
    @classmethod
    def timestamp_type(cls, value: object) -> object:
        if not isinstance(value, (str, datetime)):
            raise ValueError("Aware timestamp required")
        return value

    _utc = field_validator("approved_at", "valid_from", "valid_until")(utc)

    @model_validator(mode="after")
    def scope(self) -> "ActivityRecord":
        if not self.approved_at <= self.valid_from <= self.valid_until:
            raise ValueError("Approval must precede the bounded activity window")
        if self.valid_until - self.valid_from > timedelta(hours=1):
            raise ValueError("Authorization window exceeds one hour")
        if len({b.event_id for b in self.bindings}) != len(self.bindings):
            raise ValueError("Duplicate event binding")
        return self


class ContextAuthority(Frozen):
    """Server/custodian configuration, never a model-selectable authority."""

    tenant_id: UUID
    dataset_id: Text
    source_id: Text
    file_sha256: Digest
    authorization_reference: Text


class ContextBundle(Frozen):
    authority: ContextAuthority
    content: bytes


class ContextProof(Frozen):
    file_sha256: Digest
    row_index: Annotated[int, Field(strict=True, ge=1, le=1000)]
    raw_row_sha256: Digest
    context_record_id: UUID


class ContextCandidate(Frozen):
    predicate: Literal["approved_activity_recorded"] = "approved_activity_recorded"
    fact_id: UUID
    tenant_id: UUID
    case_id: UUID
    dataset_id: Text
    explained_fact_id: UUID
    source_id: Text
    activity: ActivityRecord
    source_proof: ContextProof
    event_proofs: Annotated[tuple[EvidenceHash, ...], Field(min_length=1, max_length=500)]
    rule_version: Literal["context-1.0"] = "context-1.0"


def context_identity(value: ContextCandidate) -> UUID:
    return stable_id(
        "verified-context",
        json_hash(value.model_dump(mode="json", exclude={"fact_id", "verification_status"})),
    )


_CAPABILITY = object()


class VerifiedContext(ContextCandidate):
    verification_status: Literal["verified"] = "verified"

    @model_validator(mode="before")
    @classmethod
    def trusted(cls, value: object, info: ValidationInfo) -> object:
        if not info.context or info.context.get("context_verifier") is not _CAPABILITY:
            raise ValueError("Independent context verification required")
        return value


def verification_capability() -> dict[str, object]:
    return {"context_verifier": _CAPABILITY}
