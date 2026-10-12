from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID

from sqlalchemy import create_engine, insert, select, text, update
from sqlalchemy.engine import Connection, RowMapping

from verisoc.core.errors import Conflict, NotFound, Unauthorized
from verisoc.core.models import (
    CanonicalEvent,
    Case,
    InvestigationReport,
    evidence_detail,
    verification_context,
)
from verisoc.core.provenance import event_hash
from verisoc.storage.models import audit, cases, datasets, events, metadata, reports, source_records

DEMO_MODE = "UNTRUSTED_SINGLE_TENANT_DEMO"


class Database:
    def __init__(self, url: str, *, demo: bool = True) -> None:
        self.engine = create_engine(url, pool_pre_ping=True)
        self.demo = demo
        if demo:
            if self.engine.dialect.name != "sqlite":
                raise ValueError("Demo requires SQLite")
            metadata.create_all(self.engine)
        elif self.engine.dialect.name != "postgresql":
            raise ValueError("Authenticated mode requires PostgreSQL")
        else:
            from verisoc.storage.rls import assert_rls

            assert_rls(self.engine)

    @contextmanager
    def scope(self, tenant: UUID) -> Iterator["Repository"]:
        if not isinstance(tenant, UUID):
            raise Unauthorized("Invalid authenticated context")
        with self.engine.begin() as conn:
            if not self.demo:
                conn.execute(
                    text("SELECT set_config('app.tenant_id', :tenant, true)"),
                    {"tenant": str(tenant)},
                )
            yield Repository(conn, tenant)


class Repository:
    def __init__(self, conn: Connection, tenant: UUID) -> None:
        self.conn, self.tenant = conn, tenant

    def _scope(self, record: Any) -> None:
        if record.tenant_id != self.tenant:
            raise NotFound("Record unavailable")

    def pin_dataset(self, name: str, file_hash: str) -> None:
        old = self.conn.execute(
            select(datasets.c.file_sha256).where(
                datasets.c.tenant_id == str(self.tenant), datasets.c.dataset_id == name
            )
        ).scalar_one_or_none()
        if old and old != file_hash:
            raise Conflict("Dataset name already pinned to different content")
        if not old:
            self.conn.execute(
                insert(datasets).values(
                    tenant_id=str(self.tenant), dataset_id=name, file_sha256=file_hash
                )
            )

    def put_event(self, event: CanonicalEvent) -> bool:
        self._scope(event)
        ref = event.source_ref
        old = self.conn.execute(
            select(source_records.c.raw_row_sha256).where(
                source_records.c.tenant_id == str(self.tenant),
                source_records.c.dataset_id == event.dataset_id,
                source_records.c.file_sha256 == ref.file_sha256,
                source_records.c.row_index == ref.row_index,
            )
        ).scalar_one_or_none()
        if old:
            if old != ref.raw_row_sha256:
                raise Conflict("Source identity conflict")
            stored = self.get_event(event.event_id)
            if stored.canonical_sha256 != event.canonical_sha256:
                raise Conflict("Canonical content conflict")
            return False
        self.conn.execute(
            insert(events).values(
                tenant_id=str(self.tenant),
                event_id=str(event.event_id),
                dataset_id=event.dataset_id,
                occurred_at=event.occurred_at.isoformat(),
                data=event.model_dump(mode="json"),
            )
        )
        self.conn.execute(
            insert(source_records).values(
                tenant_id=str(self.tenant),
                dataset_id=event.dataset_id,
                file_sha256=ref.file_sha256,
                row_index=ref.row_index,
                raw_row_sha256=ref.raw_row_sha256,
                event_id=str(event.event_id),
            )
        )
        return True

    def _event_from_row(self, row: RowMapping) -> CanonicalEvent:
        try:
            event = CanonicalEvent.model_validate(row["data"])
            self._scope(event)
            if (
                str(event.event_id) != str(row["event_id"])
                or event.dataset_id != row["dataset_id"]
                or event.occurred_at.isoformat() != row["occurred_at"]
            ):
                raise NotFound("Record unavailable")
            return event
        except (ValueError, KeyError) as exc:
            raise NotFound("Record unavailable") from exc

    def get_event(self, event_id: UUID) -> CanonicalEvent:
        row = (
            self.conn.execute(
                select(events).where(
                    events.c.tenant_id == str(self.tenant), events.c.event_id == str(event_id)
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise NotFound("Record unavailable")
        return self._event_from_row(row)

    def list_events(
        self, dataset: str, *, start: str | None = None, end: str | None = None, limit: int = 5000
    ) -> list[CanonicalEvent]:
        if not 1 <= limit <= 5000:
            raise ValueError("Invalid row limit")
        stmt = select(events).where(
            events.c.tenant_id == str(self.tenant), events.c.dataset_id == dataset
        )
        if start:
            stmt = stmt.where(events.c.occurred_at >= start)
        if end:
            stmt = stmt.where(events.c.occurred_at <= end)
        rows = self.conn.execute(
            stmt.order_by(events.c.occurred_at, events.c.event_id).limit(limit)
        ).mappings()
        return [self._event_from_row(row) for row in rows]

    def provenance_ok(self, event: CanonicalEvent) -> bool:
        self._scope(event)
        ref = event.source_ref
        row = self.conn.execute(
            select(source_records.c.raw_row_sha256).where(
                source_records.c.tenant_id == str(self.tenant),
                source_records.c.dataset_id == event.dataset_id,
                source_records.c.file_sha256 == ref.file_sha256,
                source_records.c.row_index == ref.row_index,
                source_records.c.event_id == str(event.event_id),
            )
        ).scalar_one_or_none()
        file_hash = self.conn.execute(
            select(datasets.c.file_sha256).where(
                datasets.c.tenant_id == str(self.tenant), datasets.c.dataset_id == event.dataset_id
            )
        ).scalar_one_or_none()
        return (
            file_hash == ref.file_sha256
            and row == ref.raw_row_sha256
            and event_hash(event) == event.canonical_sha256
        )

    def put_case(self, case: Case) -> None:
        self._scope(case)
        for eid in case.event_ids:
            event = self.get_event(eid)
            if (
                event.dataset_id != case.dataset_id
                or not case.start_at <= event.occurred_at <= case.end_at
            ):
                raise ValueError("Case evidence outside scope")
        old = self.conn.execute(
            select(cases.c.data).where(
                cases.c.tenant_id == str(self.tenant), cases.c.case_id == str(case.case_id)
            )
        ).scalar_one_or_none()
        data = case.model_dump(mode="json")
        if old is not None and old != data:
            raise Conflict("Case identity conflict")
        if old is None:
            self.conn.execute(
                insert(cases).values(
                    tenant_id=str(self.tenant),
                    case_id=str(case.case_id),
                    dataset_id=case.dataset_id,
                    data=data,
                )
            )

    def _case_from_row(self, row: RowMapping) -> Case:
        try:
            case = Case.model_validate(row["data"])
            self._scope(case)
            if str(case.case_id) != str(row["case_id"]) or case.dataset_id != row["dataset_id"]:
                raise NotFound("Record unavailable")
            return case
        except (ValueError, KeyError) as exc:
            raise NotFound("Record unavailable") from exc

    def get_case(self, case_id: UUID) -> Case:
        row = (
            self.conn.execute(
                select(cases).where(
                    cases.c.tenant_id == str(self.tenant), cases.c.case_id == str(case_id)
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise NotFound("Record unavailable")
        return self._case_from_row(row)

    def list_cases(self, limit: int = 100, offset: int = 0) -> list[Case]:
        if not 1 <= limit <= 100 or not 0 <= offset <= 100000:
            raise ValueError("Invalid pagination")
        rows = self.conn.execute(
            select(cases)
            .where(cases.c.tenant_id == str(self.tenant))
            .order_by(cases.c.case_id)
            .offset(offset)
            .limit(limit)
        ).mappings()
        return [self._case_from_row(row) for row in rows]

    def put_report(self, report: InvestigationReport) -> None:
        self._scope(report)
        self.get_case(report.case_id)
        for eid in report.evidence_refs:
            self.get_event(eid)
        pred = (reports.c.tenant_id == str(self.tenant)) & (
            reports.c.case_id == str(report.case_id)
        )
        data = report.model_dump(mode="json")
        old = self.conn.execute(select(reports.c.case_id).where(pred)).scalar_one_or_none()
        if old:
            self.conn.execute(update(reports).where(pred).values(data=data))
        else:
            self.conn.execute(
                insert(reports).values(
                    tenant_id=str(self.tenant), case_id=str(report.case_id), data=data
                )
            )

    def get_report(self, case_id: UUID) -> InvestigationReport:
        data = self.conn.execute(
            select(reports.c.data).where(
                reports.c.tenant_id == str(self.tenant), reports.c.case_id == str(case_id)
            )
        ).scalar_one_or_none()
        if data is None:
            raise NotFound("Record unavailable")
        result = InvestigationReport.model_validate(data, context=verification_context())
        self._scope(result)
        if result.case_id != case_id:
            raise NotFound("Record unavailable")
        from verisoc.detection.rules import APPROVED_RULES, qualified_signal
        from verisoc.verification.verifier import verify

        case = self.get_case(case_id)
        fresh = tuple(verify(self, case, d.candidate) for d in result.verified_claims)
        supported = tuple(
            d.model_copy(
                update={
                    "candidate": d.candidate.model_copy(
                        update={"explanation": "Typed predicate satisfied; no inferred intent."}
                    )
                }
            )
            for d in fresh
            if d.status == "verified"
        )
        refs = tuple(sorted({e for d in supported for e in d.supporting_event_ids}, key=str))
        details = tuple(evidence_detail(self.get_event(e)) for e in refs)
        verdict_allowed = result.verdict == "needs_review" or (
            result.verdict == "malicious"
            and not result.missing_evidence
            and not result.limit_reasons
            and case.alert is not None
            and case.alert.rule_id in APPROVED_RULES
            and set(case.alert.event_ids).issubset(refs)
            and qualified_signal(case, [self.get_event(e) for e in case.alert.event_ids])
        )
        if (
            not verdict_allowed
            or supported != result.verified_claims
            or refs != result.evidence_refs
            or details != result.evidence_details
            or any(d.status != "verified" for d in fresh)
        ):
            result = result.model_copy(
                update={
                    "verdict": "needs_review",
                    "verified_claims": supported,
                    "evidence_refs": refs,
                    "evidence_details": details,
                    "limit_reasons": result.limit_reasons + ("stored_evidence_changed",),
                }
            )
        return result

    def record_audit(self, audit_id: UUID, data: dict[str, Any]) -> None:
        self.conn.execute(
            insert(audit).values(tenant_id=str(self.tenant), audit_id=str(audit_id), data=data)
        )
