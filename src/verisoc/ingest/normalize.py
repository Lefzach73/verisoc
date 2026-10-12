from datetime import UTC, datetime
from uuid import UUID

from verisoc.core.ids import stable_id
from verisoc.core.models import Attributes, CanonicalEvent, RawEvent, SourceRef
from verisoc.core.provenance import event_hash
from verisoc.ingest.privacy import identifier, scrub


def normalize(raw: RawEvent, tenant: UUID, dataset: str, ref: SourceRef) -> CanonicalEvent:
    kind, action, outcome = {
        4624: ("windows_auth", "login", "success"),
        4625: ("windows_auth", "login", "failure"),
        4688: ("windows_process", "process_start", "success"),
        3: ("network_flow", "connect", "success"),
    }[raw.event_code]
    event = CanonicalEvent.model_validate(
        dict(
            event_id=stable_id(tenant, dataset, ref.file_sha256, ref.row_index, ref.raw_row_sha256),
            tenant_id=tenant,
            dataset_id=dataset,
            occurred_at=raw.timestamp,
            ingested_at=datetime.now(UTC),
            source_kind=kind,
            event_action=action,
            outcome=outcome,
            host_id=identifier(raw.host, tenant),
            user_id=identifier(raw.user, tenant),
            process_name=scrub(raw.process) if raw.process else None,
            src_ip=raw.src_ip,
            dst_ip=raw.dst_ip,
            src_port=raw.src_port,
            dst_port=raw.dst_port,
            attributes=Attributes(event_code=raw.event_code, message=scrub(raw.message)),
            source_ref=ref,
            canonical_sha256="0" * 64,
        )
    )
    return event.model_copy(update={"canonical_sha256": event_hash(event)})
