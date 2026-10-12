"""Authenticated v0.5 route. Context pins are server configuration, never request fields."""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header

from verisoc.api.auth import Auth
from verisoc.api.main import RateLimiter
from verisoc.api.main import create_app as legacy_app
from verisoc.core.models import Frozen
from verisoc.storage.repository import Database
from verisoc.v05.context_models import ContextBundle
from verisoc.v05.triage import TriageReport, triage


class TriageRequest(Frozen):
    """No authority, tenant or context fields may be supplied by a caller."""


def create_app(
    db: Database, auth: Auth, context_sources: tuple[ContextBundle, ...] = ()
) -> FastAPI:
    api = legacy_app(db, auth)
    api.version = "0.5-dev"
    limiter = RateLimiter()

    def principal(authorization: Annotated[str | None, Header()] = None) -> UUID:
        return auth.tenant(authorization)

    @api.post("/v05/cases/{case_id}/triage")
    def investigate(
        case_id: UUID,
        tenant: Annotated[UUID, Depends(principal)],
        body: TriageRequest | None = None,
    ) -> TriageReport:
        limiter.check(tenant)
        with db.scope(tenant) as repo:
            case = repo.get_case(case_id)
            sources = tuple(
                s
                for s in context_sources
                if s.authority.tenant_id == tenant and s.authority.dataset_id == case.dataset_id
            )
            return triage(repo, case, sources)

    return api
