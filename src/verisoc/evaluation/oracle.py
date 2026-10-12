"""Independent raw-record predicate oracle; does not trust runtime verification decisions.

This tests constrained record facts, not source authenticity, intent or human narrative labels.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from verisoc.core.ids import demo_tenant, stable_id
from verisoc.core.models import CandidateClaim, Case, RawEvent
from verisoc.core.provenance import digest, json_hash
from verisoc.ingest.privacy import scrub


@dataclass(frozen=True)
class OracleRecord:
    tenant: UUID
    dataset: str
    raw: RawEvent


class RawRecordOracle:
    def __init__(self, content: bytes, dataset: str = "demo") -> None:
        self.records: dict[UUID, OracleRecord] = {}
        seen: set[tuple[UUID, str]] = set()
        file_hash = digest(content)
        for index, line in enumerate(content.splitlines(), 1):
            obj = json.loads(line)
            tenant = demo_tenant(obj.pop("fixture_tenant"))
            raw = RawEvent.model_validate(obj)
            row_hash = json_hash(raw.model_dump(mode="json"))
            if (tenant, row_hash) in seen:
                continue
            seen.add((tenant, row_hash))
            eid = stable_id(tenant, dataset, file_hash, index, row_hash)
            self.records[eid] = OracleRecord(tenant, dataset, raw)

    @staticmethod
    def identity(value: str | None, tenant: UUID) -> str | None:
        if not value:
            return None
        return "id-" + hashlib.sha256(f"{tenant}:{value}".encode()).hexdigest()[:24]

    def supports(self, case: Case, claim: CandidateClaim) -> bool:
        records = [self.records.get(eid) for eid in claim.subject_event_ids]
        if not records or any(r is None for r in records):
            return False
        admitted = [r for r in records if r is not None]
        if any(
            r.tenant != case.tenant_id
            or r.dataset != case.dataset_id
            or not case.start_at <= r.raw.timestamp <= case.end_at
            for r in admitted
        ):
            return False
        kind = claim.claim_kind
        args = claim.parameters.model_dump(exclude_none=True)
        if kind == "analyst_inference":
            return False
        if kind in ("shared_host", "shared_user", "temporal_order"):
            if args or len(set(claim.subject_event_ids)) != len(admitted):
                return False
            if kind == "temporal_order":
                return len(admitted) == 2 and admitted[0].raw.timestamp < admitted[1].raw.timestamp
            values = [r.raw.host if kind == "shared_host" else r.raw.user for r in admitted]
            return len(values) >= 2 and all(v is not None for v in values) and len(set(values)) == 1
        code = {
            "observed_login_failure": 4625,
            "observed_login_success": 4624,
            "observed_process": 4688,
            "observed_network_connection": 3,
        }[kind]
        if len(admitted) != 1 or admitted[0].raw.event_code != code:
            return False
        raw = admitted[0].raw
        fields: dict[str, Any] = {
            "host_id": self.identity(raw.host, case.tenant_id),
            "user_id": self.identity(raw.user, case.tenant_id),
            "process_name": scrub(raw.process) if raw.process else None,
            "src_ip": raw.src_ip,
            "dst_ip": raw.dst_ip,
            "dst_port": raw.dst_port,
        }
        allowed = {
            4624: {"host_id", "user_id"},
            4625: {"host_id", "user_id"},
            4688: {"host_id", "process_name"},
            3: {"src_ip", "dst_ip", "dst_port"},
        }[code]
        for field, value in args.items():
            if field == "start_at":
                if raw.timestamp < value:
                    return False
            elif field == "end_at":
                if raw.timestamp > value:
                    return False
            elif field not in allowed or fields[field] != value:
                return False
        return True
