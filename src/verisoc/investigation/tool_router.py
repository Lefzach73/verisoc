from datetime import datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, ValidationError, field_validator

from verisoc.core.errors import BudgetExceeded, NotFound, Unauthorized, VeriSOCError
from verisoc.core.models import CandidateReport, CanonicalEvent, Case, Frozen, utc
from verisoc.ingest.privacy import scrub
from verisoc.storage.repository import Repository


class CaseArgs(Frozen):
    case_id: UUID


class SearchArgs(CaseArgs):
    start: datetime
    end: datetime
    limit: Annotated[int, Field(ge=1, le=64, strict=True)] = 32
    source_kind: Literal["windows_auth", "windows_process", "network_flow"] | None = None
    _time = field_validator("start", "end")(utc)


class RelatedArgs(CaseArgs):
    event_id: UUID
    relation: Literal["host", "user", "ip"]
    limit: Annotated[int, Field(ge=1, le=64, strict=True)] = 32


class EvidenceArgs(Frozen):
    event_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=64)]


TOOL_SCHEMAS: dict[str, type[Frozen]] = {
    "get_case": CaseArgs,
    "search_events": SearchArgs,
    "get_related": RelatedArgs,
    "get_evidence": EvidenceArgs,
    "submit_candidate_report": CandidateReport,
}


def project(event: CanonicalEvent) -> dict[str, Any]:
    # Omit arbitrary message text, raw source records, IPs and operational admission time.
    return {
        "event_id": str(event.event_id),
        "occurred_at": event.occurred_at.isoformat(),
        "source_kind": event.source_kind,
        "event_action": event.event_action,
        "outcome": event.outcome,
        "host_id": event.host_id,
        "user_id": event.user_id,
        "process_name": scrub(event.process_name) if event.process_name else None,
        "dst_port": event.dst_port,
        "canonical_sha256": event.canonical_sha256,
    }


class ToolRouter:
    def __init__(self, repo: Repository, case: Case, *, max_calls: int = 8) -> None:
        repo._scope(case)
        self.repo, self.case, self.max_calls = repo, case, max_calls
        self.calls = 0
        self.trace: list[dict[str, Any]] = []

    def event(self, eid: UUID) -> CanonicalEvent:
        event = self.repo.get_event(eid)
        if (
            event.dataset_id != self.case.dataset_id
            or not self.case.start_at <= event.occurred_at <= self.case.end_at
        ):
            raise NotFound("Record unavailable")
        if not self.repo.provenance_ok(event):
            raise NotFound("Record unavailable")
        return event

    def scoped_events(self) -> list[CanonicalEvent]:
        if self.case.end_at - self.case.start_at > timedelta(hours=24):
            raise BudgetExceeded("Case time span exceeded")
        records = self.repo.list_events(
            self.case.dataset_id,
            start=self.case.start_at.isoformat(),
            end=self.case.end_at.isoformat(),
            limit=5000,
        )
        return [e for e in records if self.repo.provenance_ok(e)]

    def execute(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            return self._execute(name, arguments)
        except (VeriSOCError, ValidationError, ValueError) as exc:
            self.trace.append(
                {
                    "tool": name if name in TOOL_SCHEMAS else "unavailable",
                    "call": self.calls,
                    "result_count": 0,
                    "status": "rejected",
                    "reason": exc.code if isinstance(exc, VeriSOCError) else "invalid_arguments",
                }
            )
            raise

    def _execute(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls += 1
        if self.calls > self.max_calls:
            raise BudgetExceeded("Tool budget exceeded")
        if name not in TOOL_SCHEMAS:
            raise Unauthorized("Tool unavailable")
        args = TOOL_SCHEMAS[name].model_validate(arguments)
        if isinstance(args, CaseArgs) and args.case_id != self.case.case_id:
            raise NotFound("Record unavailable")
        result: Any
        if isinstance(args, SearchArgs):
            if (
                args.start > args.end
                or args.start < self.case.start_at
                or args.end > self.case.end_at
                or args.end - args.start > timedelta(hours=24)
            ):
                raise NotFound("Record unavailable")
            rows = [
                e
                for e in self.scoped_events()
                if args.start <= e.occurred_at <= args.end
                and (args.source_kind is None or e.source_kind == args.source_kind)
            ]
            result = [project(e) for e in rows[: args.limit]]
        elif isinstance(args, RelatedArgs):
            event = self.event(args.event_id)
            field = {"host": "host_id", "user": "user_id", "ip": "src_ip"}[args.relation]
            value = getattr(event, field)
            result = [
                project(e)
                for e in self.scoped_events()
                if value is not None and getattr(e, field) == value
            ][: args.limit]
        elif isinstance(args, EvidenceArgs):
            result = [project(self.event(e)) for e in args.event_ids]
        elif isinstance(args, CandidateReport):
            result = args.model_dump(
                mode="json"
            )  # Proposal only; publication occurs after verification.
        else:
            result = self.case.model_dump(mode="json")
        self.trace.append(
            {
                "tool": name,
                "call": self.calls,
                "result_count": len(result) if isinstance(result, list) else 1,
            }
        )
        return result
