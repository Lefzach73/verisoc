"""Raw-file fact oracle: no producer, registry or runtime fact-verifier imports."""

import json
from datetime import timedelta
from typing import Literal
from uuid import UUID

from verisoc.core.ids import demo_tenant, stable_id
from verisoc.core.models import Case, RawEvent
from verisoc.core.provenance import digest, json_hash
from verisoc.evaluation.oracle import OracleRecord, RawRecordOracle
from verisoc.evidence.models import EvidenceHash, FactCandidate
from verisoc.ingest.privacy import scrub


class RawFactOracle(RawRecordOracle):
    def __init__(self, content: bytes, dataset: str = "demo") -> None:
        super().__init__(content, dataset)
        self.proofs: dict[UUID, EvidenceHash] = {}
        file_hash = digest(content)
        for index, line in enumerate(content.splitlines(), 1):
            obj = json.loads(line)
            tenant = demo_tenant(obj.pop("fixture_tenant"))
            raw = RawEvent.model_validate(obj)
            row_hash = json_hash(raw.model_dump(mode="json"))
            eid = stable_id(tenant, dataset, file_hash, index, row_hash)
            if eid not in self.records:
                continue
            ref = dict(file_sha256=file_hash, row_index=index, raw_row_sha256=row_hash)
            kind = (
                "windows_auth"
                if raw.event_code in (4624, 4625)
                else ("windows_process" if raw.event_code == 4688 else "network_flow")
            )
            canonical = dict(
                schema_version="1.0",
                event_id=str(eid),
                tenant_id=str(tenant),
                dataset_id=dataset,
                occurred_at=raw.model_dump(mode="json")["timestamp"],
                source_kind=kind,
                event_action="login"
                if raw.event_code in (4624, 4625)
                else ("process_start" if raw.event_code == 4688 else "connect"),
                outcome="failure" if raw.event_code == 4625 else "success",
                host_id=self.identity(raw.host, tenant),
                user_id=self.identity(raw.user, tenant),
                src_ip=str(raw.src_ip) if raw.src_ip else None,
                dst_ip=str(raw.dst_ip) if raw.dst_ip else None,
                src_port=raw.src_port,
                dst_port=raw.dst_port,
                process_name=scrub(raw.process) if raw.process else None,
                attributes=dict(event_code=raw.event_code, message=scrub(raw.message)),
                source_ref=ref,
            )
            self.proofs[eid] = EvidenceHash(
                event_id=eid,
                canonical_sha256=json_hash(canonical),
                file_sha256=file_hash,
                row_index=index,
                raw_row_sha256=row_hash,
            )

    def supports_fact(self, case: Case, fact: FactCandidate) -> bool:
        if (
            fact.tenant_id != case.tenant_id
            or fact.case_id != case.case_id
            or fact.dataset_id != case.dataset_id
        ):
            return False
        if fact.derivation_rule_version != "1.0":
            return False
        cited = [self.records.get(eid) for eid in fact.source_event_ids]
        if not cited or any(r is None for r in cited):
            return False
        records = [r for r in cited if r is not None]
        if any(
            r.tenant != case.tenant_id
            or r.dataset != case.dataset_id
            or not case.start_at <= r.raw.timestamp <= case.end_at
            for r in records
        ):
            return False
        if fact.evidence_hashes != tuple(self.proofs[eid] for eid in fact.source_event_ids):
            return False
        a = fact.arguments

        def identity(r: OracleRecord, field: Literal["host", "user"]) -> str | None:
            value = r.raw.host if field == "host" else r.raw.user
            return self.identity(value, case.tenant_id)

        expected: dict[str, object] = dict(
            event_code=None,
            outcome=None,
            host_id=None,
            user_id=None,
            process_name=None,
            src_ip=None,
            dst_ip=None,
            dst_port=None,
            start_at=a.start_at,
            end_at=a.end_at,
            event_count=len(records),
            distinct_users=None,
        )
        if fact.predicate == "observed_event":
            if fact.derivation_rule_id != "record-observation" or len(records) != 1:
                return False
            raw = records[0].raw
            expected.update(
                event_code=raw.event_code,
                outcome="failure" if raw.event_code == 4625 else "success",
                host_id=identity(records[0], "host"),
                user_id=identity(records[0], "user"),
                process_name=scrub(raw.process) if raw.process else None,
                src_ip=raw.src_ip,
                dst_ip=raw.dst_ip,
                dst_port=raw.dst_port,
                start_at=raw.timestamp,
                end_at=raw.timestamp,
            )
        elif fact.predicate == "windows_image_match":
            if fact.derivation_rule_id != "windows-lab-image" or len(records) != 1:
                return False
            raw = records[0].raw
            # Independent basename implementation, not the producer's ntpath call.
            basename = (raw.process or "").replace("\\", "/").split("/")[-1].casefold()
            if len(basename) >= 2 and basename[1] == ":":
                basename = basename[2:]
            if raw.event_code != 4688 or basename != "lab-indicator.exe":
                return False
            expected.update(
                host_id=identity(records[0], "host"),
                process_name="lab-indicator.exe",
                start_at=raw.timestamp,
                end_at=raw.timestamp,
            )
        else:
            known = {
                "failed_login_burst": "auth-failure-count",
                "multi_account_failures": "host-account-failure-count",
                "source_account_failures": "source-account-failure-count",
                "success_after_failures": "ordered-auth-sequence",
            }
            if known.get(fact.predicate) != fact.derivation_rule_id:
                return False
            if not a.host_id or not case.start_at <= a.start_at <= a.end_at <= case.end_at:
                return False
            if a.start_at != max(case.start_at, a.end_at - timedelta(seconds=300)):
                return False
            if fact.predicate in ("failed_login_burst", "success_after_failures") and not a.user_id:
                return False
            if fact.predicate == "source_account_failures" and a.src_ip is None:
                return False
            wanted = []
            for eid, r in self.records.items():
                if (
                    r.tenant != case.tenant_id
                    or r.dataset != case.dataset_id
                    or r.raw.event_code != 4625
                    or not r.raw.user
                ):
                    continue
                if (
                    not a.start_at <= r.raw.timestamp <= a.end_at
                    or identity(r, "host") != a.host_id
                ):
                    continue
                if (
                    fact.predicate in ("failed_login_burst", "success_after_failures")
                    and identity(r, "user") != a.user_id
                ):
                    continue
                if fact.predicate == "source_account_failures" and r.raw.src_ip != a.src_ip:
                    continue
                if fact.predicate == "success_after_failures" and r.raw.timestamp == a.end_at:
                    continue
                wanted.append((eid, r))
            distinct = len({r.raw.user for _, r in wanted})
            if len(wanted) < 5:
                return False
            if (
                fact.predicate in ("multi_account_failures", "source_account_failures")
                and distinct < 5
            ):
                return False
            if fact.predicate == "success_after_failures":
                success = [
                    (eid, self.records[eid])
                    for eid in fact.source_event_ids
                    if self.records[eid].raw.event_code == 4624
                ]
                if len(success) != 1:
                    return False
                _, record = success[0]
                if (
                    record.raw.timestamp != a.end_at
                    or identity(record, "host") != a.host_id
                    or identity(record, "user") != a.user_id
                ):
                    return False
                wanted.extend(success)
            wanted.sort(key=lambda pair: (pair[1].raw.timestamp, str(pair[0])))
            if tuple(eid for eid, _ in wanted) != fact.source_event_ids:
                return False
            expected.update(
                host_id=a.host_id,
                user_id=a.user_id
                if fact.predicate in ("failed_login_burst", "success_after_failures")
                else None,
                src_ip=a.src_ip if fact.predicate == "source_account_failures" else None,
                distinct_users=distinct
                if fact.predicate in ("multi_account_failures", "source_account_failures")
                else None,
            )
        return a.model_dump() == expected
