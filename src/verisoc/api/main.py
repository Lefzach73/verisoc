import os
import threading
import time
from collections import defaultdict, deque
from typing import Annotated, Any
from uuid import UUID

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import Field

from verisoc.api.auth import Auth
from verisoc.core.errors import NotFound, RateLimited, Unauthorized, VeriSOCError
from verisoc.core.models import Case, Frozen, ImportManifest, InvestigationReport
from verisoc.detection.rules import detect
from verisoc.evidence.registry import EvidenceRegistry, FactCache
from verisoc.ingest.importer import MAX_BYTES, import_jsonl
from verisoc.investigation.evidence_pipeline import (
    CaseWindow,
    EvidencePacket,
    EvidenceReport,
    FactRouter,
    FactView,
    investigate_evidence,
    open_window,
)
from verisoc.investigation.pipeline import investigate as run_investigation
from verisoc.llm.base import Budget
from verisoc.llm.mock import MockProvider
from verisoc.storage.repository import DEMO_MODE, Database


class ImportRequest(Frozen):
    dataset_id: Annotated[str, Field(min_length=1, max_length=256)]
    jsonl: Annotated[str, Field(min_length=1, max_length=MAX_BYTES)]


class DetectRequest(Frozen):
    dataset_id: Annotated[str, Field(min_length=1, max_length=256)]


class ErrorResponse(Frozen):
    error: str


class RateLimiter:
    def __init__(self, cap: int = 30) -> None:
        self.cap = cap
        self.buckets: dict[UUID, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, tenant: UUID) -> None:
        with self.lock:
            now = time.monotonic()
            queue = self.buckets[tenant]
            while queue and now - queue[0] > 60:
                queue.popleft()
            if len(queue) >= self.cap:
                raise RateLimited("Rate limit exceeded")
            queue.append(now)


def create_app(database: Database | None = None, auth: Auth | None = None) -> FastAPI:
    if database is None:
        demo = os.getenv("VERISOC_MODE") == "single-tenant-demo"
        url = os.environ["VERISOC_DATABASE_URL"]
        database = Database(url, demo=demo)
    if auth is None:
        auth = Auth(os.environ["VERISOC_SIGNING_KEY"])
    db, token_auth = database, auth
    api = FastAPI(
        title="VeriSOC Research",
        version="0.4.0",
        description=DEMO_MODE if db.demo else "Authenticated PostgreSQL RLS research mode",
        responses={
            401: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
            422: {"model": ErrorResponse},
            429: {"model": ErrorResponse},
        },
    )
    limiter = RateLimiter()
    fact_cache = FactCache()

    @api.middleware("http")
    async def size_limit(request: Request, call_next: Any) -> Any:
        # Stream limit also handles missing/fake Content-Length. No unbounded body buffering.
        if request.method == "POST":
            content = bytearray()
            async for chunk in request.stream():
                content.extend(chunk)
                if len(content) > MAX_BYTES + 65536:
                    return JSONResponse(status_code=413, content={"error": "request_too_large"})
            request._body = bytes(content)
        return await call_next(request)

    @api.exception_handler(VeriSOCError)
    async def domain_error(request: Request, exc: VeriSOCError) -> JSONResponse:
        status = 404 if isinstance(exc, NotFound) else 401 if isinstance(exc, Unauthorized) else 422
        if isinstance(exc, RateLimited):
            status = 429
        return JSONResponse(status_code=status, content={"error": exc.code})

    @api.exception_handler(RequestValidationError)
    async def request_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"error": "invalid_request"})

    @api.exception_handler(ValueError)
    async def value_error(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"error": "invalid_request"})

    def principal(authorization: Annotated[str | None, Header()] = None) -> UUID:
        return token_auth.tenant(authorization)

    @api.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": DEMO_MODE if db.demo else "AUTHENTICATED_POSTGRES_RLS"}

    @api.post("/v1/events/import")
    def ingest(body: ImportRequest, tenant: Annotated[UUID, Depends(principal)]) -> ImportManifest:
        limiter.check(tenant)
        with db.scope(tenant) as repo:
            return import_jsonl(repo, body.jsonl.encode(), body.dataset_id)

    @api.post("/v1/cases/detect")
    def detection(body: DetectRequest, tenant: Annotated[UUID, Depends(principal)]) -> list[Case]:
        limiter.check(tenant)
        with db.scope(tenant) as repo:
            return detect(repo, body.dataset_id)

    @api.get("/v1/cases")
    def list_cases(
        tenant: Annotated[UUID, Depends(principal)],
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        offset: Annotated[int, Query(ge=0, le=100000)] = 0,
    ) -> list[Case]:
        with db.scope(tenant) as repo:
            return repo.list_cases(limit, offset)

    @api.get("/v1/cases/{case_id}")
    def case_detail(case_id: UUID, tenant: Annotated[UUID, Depends(principal)]) -> Case:
        with db.scope(tenant) as repo:
            return repo.get_case(case_id)

    @api.post("/v1/cases/{case_id}/investigate", response_model=InvestigationReport)
    def investigate(
        case_id: UUID, tenant: Annotated[UUID, Depends(principal)]
    ) -> InvestigationReport:
        limiter.check(tenant)
        with db.scope(tenant) as repo:
            case = repo.get_case(case_id)
            return run_investigation(repo, case, MockProvider(), Budget())

    @api.get("/v1/cases/{case_id}/report", response_model=InvestigationReport)
    def report(case_id: UUID, tenant: Annotated[UUID, Depends(principal)]) -> InvestigationReport:
        with db.scope(tenant) as repo:
            return repo.get_report(case_id)

    @api.post("/v1/evidence/cases")
    def evidence_case(body: CaseWindow, tenant: Annotated[UUID, Depends(principal)]) -> Case:
        limiter.check(tenant)
        with db.scope(tenant) as repo:
            return open_window(repo, body)

    @api.get("/v1/cases/{case_id}/facts")
    def fact_packet(
        case_id: UUID,
        tenant: Annotated[UUID, Depends(principal)],
        offset: Annotated[int, Query(ge=0, le=5000)] = 0,
    ) -> EvidencePacket:
        limiter.check(tenant)
        with db.scope(tenant) as repo:
            registry = EvidenceRegistry(repo, repo.get_case(case_id), fact_cache)
            return FactRouter(registry).packet(offset=offset)

    @api.get("/v1/cases/{case_id}/facts/{fact_id}")
    def fact_detail(
        case_id: UUID, fact_id: UUID, tenant: Annotated[UUID, Depends(principal)]
    ) -> FactView:
        limiter.check(tenant)
        with db.scope(tenant) as repo:
            registry = EvidenceRegistry(repo, repo.get_case(case_id), fact_cache)
            return FactRouter(registry).get(fact_id)

    @api.post("/v1/cases/{case_id}/investigate-v04")
    def evidence_report(
        case_id: UUID, tenant: Annotated[UUID, Depends(principal)]
    ) -> EvidenceReport:
        limiter.check(tenant)
        with db.scope(tenant) as repo:
            return investigate_evidence(repo, repo.get_case(case_id), cache=fact_cache)

    return api
