from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    ValidationInfo,
    field_validator,
    model_validator,
)

Text = Annotated[str, Field(min_length=1, max_length=256)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Verdict = Literal["malicious", "benign", "needs_review"]
Kind = Literal[
    "observed_process",
    "observed_login_failure",
    "observed_login_success",
    "observed_network_connection",
    "shared_host",
    "shared_user",
    "temporal_order",
    "analyst_inference",
]


def utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timezone required")
    return value.astimezone(UTC)


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", validate_default=True)


class Attributes(Frozen):
    event_code: Literal[4624, 4625, 4688, 3]
    message: Annotated[str, Field(max_length=2048)] = ""


class SourceRef(Frozen):
    file_sha256: Digest
    row_index: Annotated[int, Field(ge=1, le=5000)]
    raw_row_sha256: Digest


class RawEvent(Frozen):
    event_code: Literal[4624, 4625, 4688, 3]
    timestamp: datetime
    host: Text | None = None
    user: Text | None = None
    process: Text | None = None
    src_ip: IPvAnyAddress | None = None
    dst_ip: IPvAnyAddress | None = None
    src_port: Annotated[int, Field(ge=0, le=65535, strict=True)] | None = None
    dst_port: Annotated[int, Field(ge=0, le=65535, strict=True)] | None = None
    message: Annotated[str, Field(max_length=2048)] = ""

    @field_validator("timestamp", mode="before")
    @classmethod
    def timestamp_type(cls, value: object) -> object:
        if not isinstance(value, (str, datetime)):
            raise ValueError("RFC3339 timestamp string or aware datetime required")
        return value

    _time = field_validator("timestamp")(utc)


class CanonicalEvent(Frozen):
    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    tenant_id: UUID
    dataset_id: Text
    occurred_at: datetime
    ingested_at: datetime
    source_kind: Literal["windows_auth", "windows_process", "network_flow"]
    event_action: Literal["login", "process_start", "connect"]
    outcome: Literal["success", "failure", "unknown"]
    host_id: Text | None = None
    user_id: Text | None = None
    src_ip: IPvAnyAddress | None = None
    dst_ip: IPvAnyAddress | None = None
    src_port: Annotated[int, Field(ge=0, le=65535, strict=True)] | None = None
    dst_port: Annotated[int, Field(ge=0, le=65535, strict=True)] | None = None
    process_name: Text | None = None
    attributes: Attributes
    source_ref: SourceRef
    canonical_sha256: Digest
    _time = field_validator("occurred_at", "ingested_at")(utc)

    @model_validator(mode="after")
    def consistent(self) -> "CanonicalEvent":
        expected = {
            4624: ("windows_auth", "login", "success"),
            4625: ("windows_auth", "login", "failure"),
            4688: ("windows_process", "process_start", "success"),
            3: ("network_flow", "connect", "success"),
        }[self.attributes.event_code]
        if (self.source_kind, self.event_action, self.outcome) != expected:
            raise ValueError("Inconsistent event semantics")
        return self


class Alert(Frozen):
    schema_version: Literal["1.0"] = "1.0"
    alert_id: UUID
    tenant_id: UUID
    dataset_id: Text
    rule_id: Text
    rule_version: Text = "native-1.0"
    title: Text
    severity: Literal["low", "medium", "high"]
    event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=500)]
    start_at: datetime
    end_at: datetime
    _time = field_validator("start_at", "end_at")(utc)


class Case(Frozen):
    schema_version: Literal["1.0"] = "1.0"
    case_id: UUID
    tenant_id: UUID
    dataset_id: Text
    event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=500)]
    start_at: datetime
    end_at: datetime
    alert: Alert | None = None
    _time = field_validator("start_at", "end_at")(utc)

    @model_validator(mode="after")
    def coherent(self) -> "Case":
        if self.start_at > self.end_at:
            raise ValueError("Reversed case interval")
        if self.alert and (
            self.alert.tenant_id != self.tenant_id
            or self.alert.dataset_id != self.dataset_id
            or not set(self.alert.event_ids).issubset(self.event_ids)
        ):
            raise ValueError("Inconsistent case alert")
        return self


class PredicateArgs(Frozen):
    host_id: Text | None = None
    user_id: Text | None = None
    process_name: Text | None = None
    src_ip: IPvAnyAddress | None = None
    dst_ip: IPvAnyAddress | None = None
    dst_port: Annotated[int, Field(ge=0, le=65535, strict=True)] | None = None
    start_at: datetime | None = None
    end_at: datetime | None = None

    @field_validator("start_at", "end_at")
    @classmethod
    def time(cls, value: datetime | None) -> datetime | None:
        return utc(value) if value is not None else None

    @model_validator(mode="after")
    def order(self) -> "PredicateArgs":
        if self.start_at and self.end_at and self.start_at > self.end_at:
            raise ValueError("Reversed predicate interval")
        return self


class CandidateClaim(Frozen):
    claim_id: UUID
    claim_kind: Kind
    subject_event_ids: Annotated[tuple[UUID, ...], Field(max_length=32)]
    parameters: PredicateArgs = Field(default_factory=PredicateArgs)
    explanation: Annotated[str, Field(max_length=1024)] = ""


class CandidateReport(Frozen):
    claims: Annotated[tuple[CandidateClaim, ...], Field(max_length=64)]
    proposed_verdict: Verdict
    uncertainties: Annotated[tuple[Text, ...], Field(max_length=16)] = ()


_VERIFICATION_CAPABILITY = object()


def verification_context() -> dict[str, object]:
    """Internal code capability; never pass this context to model deserialization."""
    return {"verification_capability": _VERIFICATION_CAPABILITY}


class VerifiedClaim(Frozen):
    @model_validator(mode="before")
    @classmethod
    def verifier_only(cls, value: object, info: ValidationInfo) -> object:
        if (
            not info.context
            or info.context.get("verification_capability") is not _VERIFICATION_CAPABILITY
        ):
            raise ValueError("Verification decisions require trusted verifier context")
        return value

    candidate: CandidateClaim
    status: Literal["verified", "rejected", "insufficient"]
    verifier_id: Text
    supporting_event_ids: tuple[UUID, ...]
    reason_code: Text


class EvidenceDetail(Frozen):
    event_id: UUID
    occurred_at: datetime
    source_kind: Literal["windows_auth", "windows_process", "network_flow"]
    outcome: Literal["success", "failure", "unknown"]
    host_id: Text | None = None
    user_id: Text | None = None
    process_name: Text | None = None
    dst_port: int | None = None
    source_ref: SourceRef
    canonical_sha256: Digest
    _time = field_validator("occurred_at")(utc)


def evidence_detail(event: CanonicalEvent) -> EvidenceDetail:
    return EvidenceDetail.model_validate(event.model_dump(include=set(EvidenceDetail.model_fields)))


class InvestigationReport(Frozen):
    schema_version: Literal["1.0"] = "1.0"
    report_id: UUID
    case_id: UUID
    tenant_id: UUID
    verdict: Verdict
    verified_claims: tuple[VerifiedClaim, ...]
    hypotheses: tuple[CandidateClaim, ...]
    missing_evidence: tuple[Text, ...]
    limit_reasons: tuple[Text, ...]
    evidence_refs: tuple[UUID, ...]
    evidence_details: tuple[EvidenceDetail, ...] = ()
    run_manifest_id: Text
    provider_id: Text
    model_id: Text
    tokens_input: Annotated[int, Field(ge=0)] = 0
    tokens_output: Annotated[int, Field(ge=0)] = 0
    estimated_usd: Annotated[float, Field(ge=0, allow_inf_nan=False)] = 0
    total_duration_ms: Annotated[float, Field(ge=0, allow_inf_nan=False)] = 0


class ImportManifest(Frozen):
    tenant_id: UUID
    dataset_id: Text
    file_sha256: Digest
    accepted: int
    duplicates: int
    event_ids: tuple[UUID, ...]
    mode: Text
