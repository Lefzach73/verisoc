"""Independent source-file indexing for authorized single-tenant prospective event files."""

import json
from uuid import UUID

from verisoc.core.ids import stable_id
from verisoc.core.models import RawEvent
from verisoc.core.provenance import digest, json_hash
from verisoc.evaluation.fact_oracle import RawFactOracle
from verisoc.evaluation.oracle import OracleRecord
from verisoc.evidence.models import EvidenceHash
from verisoc.ingest.privacy import scrub


class SingleTenantOracle(RawFactOracle):
    def __init__(self, content: bytes, tenant: UUID, dataset: str) -> None:
        self.records = {}
        self.proofs = {}
        seen = set()
        file_hash = digest(content)
        for index, line in enumerate(content.splitlines(), 1):
            raw = RawEvent.model_validate(json.loads(line))
            row_hash = json_hash(raw.model_dump(mode="json"))
            if row_hash in seen:
                continue
            seen.add(row_hash)
            eid = stable_id(tenant, dataset, file_hash, index, row_hash)
            self.records[eid] = OracleRecord(tenant, dataset, raw)
            source = dict(file_sha256=file_hash, row_index=index, raw_row_sha256=row_hash)
            auth = raw.event_code in (4624, 4625)
            canonical = dict(
                schema_version="1.0",
                event_id=str(eid),
                tenant_id=str(tenant),
                dataset_id=dataset,
                occurred_at=raw.model_dump(mode="json")["timestamp"],
                source_kind="windows_auth"
                if auth
                else "windows_process"
                if raw.event_code == 4688
                else "network_flow",
                event_action="login"
                if auth
                else "process_start"
                if raw.event_code == 4688
                else "connect",
                outcome="failure" if raw.event_code == 4625 else "success",
                host_id=self.identity(raw.host, tenant),
                user_id=self.identity(raw.user, tenant),
                process_name=scrub(raw.process) if raw.process else None,
                src_ip=str(raw.src_ip) if raw.src_ip else None,
                dst_ip=str(raw.dst_ip) if raw.dst_ip else None,
                src_port=raw.src_port,
                dst_port=raw.dst_port,
                attributes=dict(event_code=raw.event_code, message=scrub(raw.message)),
                source_ref=source,
            )
            self.proofs[eid] = EvidenceHash(
                event_id=eid,
                canonical_sha256=json_hash(canonical),
                file_sha256=file_hash,
                row_index=index,
                raw_row_sha256=row_hash,
            )
