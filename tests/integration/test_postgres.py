import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import insert, select, text
from sqlalchemy.exc import DBAPIError

from verisoc.api.auth import Auth
from verisoc.api.main import create_app
from verisoc.core.errors import NotFound
from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect
from verisoc.ingest.importer import import_jsonl
from verisoc.storage.models import datasets, events, metadata
from verisoc.storage.repository import Database

pytestmark = pytest.mark.postgres
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def pg():
    url = os.getenv("VERISOC_TEST_DATABASE_URL")
    if not url:
        pytest.fail("Real PostgreSQL test URL required; use make test-integration")
    db = Database(url, demo=False)
    for name in ("demo-a", "demo-b"):
        with db.scope(demo_tenant(name)) as repo:
            import_jsonl(
                repo,
                (ROOT / "fixtures/demo/events.jsonl").read_bytes(),
                "demo",
                fixture_tenant=name,
            )
            detect(repo, "demo")
    yield db
    db.engine.dispose()


def test_force_rls_every_tenant_table_and_non_owner(pg):
    with pg.engine.connect() as conn:
        role = conn.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")
        ).one()
        assert not role.rolsuper and not role.rolbypassrls
        for name in metadata.tables:
            flags = conn.execute(
                text(
                    "SELECT relrowsecurity, relforcerowsecurity, "
                    "pg_has_role(current_user,relowner,'USAGE') "
                    "FROM pg_class WHERE relname=:name"
                ),
                {"name": name},
            ).one()
            assert flags == (True, True, False)
            assert conn.execute(select(metadata.tables[name])).first() is None


def test_rls_catches_missing_application_filter_and_write(pg):
    for name in ("demo-a", "demo-b"):
        with pg.scope(demo_tenant(name)) as repo:
            all_rows = repo.conn.execute(select(events.c.tenant_id)).scalars().all()
            assert len(all_rows) == 236 and set(map(str, all_rows)) == {str(demo_tenant(name))}
    with pytest.raises(DBAPIError), pg.scope(demo_tenant("demo-a")) as repo:
        repo.conn.execute(
            insert(datasets).values(
                tenant_id=str(demo_tenant("demo-b")),
                dataset_id="forged-write",
                file_sha256="0" * 64,
            )
        )


def test_missing_context_and_transaction_reset(pg):
    with pg.scope(demo_tenant("demo-a")) as repo:
        assert repo.conn.execute(select(events.c.event_id)).first()
    with pg.engine.begin() as conn:
        assert conn.execute(select(events.c.event_id)).first() is None
    with pytest.raises(DBAPIError), pg.engine.begin() as conn:
        conn.execute(
            insert(datasets).values(
                tenant_id=str(demo_tenant("demo-a")), dataset_id="unset", file_sha256="0" * 64
            )
        )


def test_foreign_lookup_and_api_schema(pg):
    with pg.scope(demo_tenant("demo-b")) as repo:
        foreign = repo.list_cases()[0]
    with pg.scope(demo_tenant("demo-a")) as repo:
        for eid in (foreign.event_ids[0], uuid4()):
            with pytest.raises(NotFound, match="Record unavailable"):
                repo.get_event(eid)
    assert create_app(pg, Auth("synthetic-postgres-test-key-32-bytes")).openapi()["paths"]


def test_application_refuses_owner_and_disabled_rls(pg):
    admin = os.environ["VERISOC_TEST_ADMIN_URL"]
    with pytest.raises(ValueError, match="Restricted non-owner"):
        Database(admin.replace("postgresql://", "postgresql+psycopg://"), demo=False)
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute("ALTER TABLE reports NO FORCE ROW LEVEL SECURITY")
        try:
            with pytest.raises(ValueError, match="unsafe row-level security"):
                Database(os.environ["VERISOC_TEST_DATABASE_URL"], demo=False)
        finally:
            conn.execute("ALTER TABLE reports FORCE ROW LEVEL SECURITY")


def test_startup_refuses_permissive_policy_and_excess_grants(pg):
    admin = os.environ["VERISOC_TEST_ADMIN_URL"]
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute("ALTER POLICY tenant_scope ON reports USING (true) WITH CHECK (true)")
        try:
            with pytest.raises(ValueError, match="policy expression"):
                Database(os.environ["VERISOC_TEST_DATABASE_URL"], demo=False)
        finally:
            conn.execute(
                "ALTER POLICY tenant_scope ON reports "
                "USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid) "
                "WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)"
            )
        conn.execute("GRANT TRUNCATE ON events TO verisoc_app")
        try:
            with pytest.raises(ValueError, match="unsafe row-level"):
                Database(os.environ["VERISOC_TEST_DATABASE_URL"], demo=False)
        finally:
            conn.execute("REVOKE TRUNCATE ON events FROM verisoc_app")
        conn.execute("GRANT UPDATE ON events TO verisoc_app")
        try:
            with pytest.raises(ValueError, match="Immutable evidence"):
                Database(os.environ["VERISOC_TEST_DATABASE_URL"], demo=False)
        finally:
            conn.execute("REVOKE UPDATE ON events FROM verisoc_app")


def test_rls_applies_api_foreign_reports_on_real_pg(pg):
    from datetime import UTC, datetime, timedelta

    import jwt
    from fastapi.testclient import TestClient

    key = "synthetic-postgres-api-test-key-32-bytes"
    now = datetime.now(UTC)

    def headers(name):
        return {
            "Authorization": "Bearer "
            + jwt.encode(
                dict(
                    sub="test",
                    tenant_id=str(demo_tenant(name)),
                    iss="verisoc-research",
                    aud="verisoc-api",
                    iat=now,
                    nbf=now,
                    exp=now + timedelta(minutes=5),
                ),
                key,
                algorithm="HS256",
            )
        }

    client = TestClient(create_app(pg, Auth(key)))
    cases = client.get("/v1/cases", headers=headers("demo-a")).json()
    cid = cases[0]["case_id"]
    assert client.post(f"/v1/cases/{cid}/investigate", headers=headers("demo-a")).status_code == 200
    assert client.get(f"/v1/cases/{cid}/report", headers=headers("demo-b")).json() == {
        "error": "not_found"
    }
    assert client.get(f"/v1/cases/{cid}/report", headers=headers("demo-a")).status_code == 200


def test_v04_verified_fact_registry_uses_real_rls_scope(pg):
    from verisoc.evidence.registry import EvidenceRegistry, FactCache
    from verisoc.verification.facts import verify_fact

    cache = FactCache()
    with pg.scope(demo_tenant("demo-a")) as repo:
        case = repo.list_cases()[0]
        registry = EvidenceRegistry(repo, case, cache)
        fact = next(iter(registry.facts.values()))
        assert registry.get(fact.fact_id).tenant_id == repo.tenant
    with pg.scope(demo_tenant("demo-b")) as repo:
        own = repo.list_cases()[0]
        other = EvidenceRegistry(repo, own, cache)
        assert verify_fact(repo, own, fact).status == "rejected"
        with pytest.raises(NotFound):
            other.get(fact.fact_id)
        with pytest.raises(NotFound):
            EvidenceRegistry(repo, case, cache)


def test_v04_pipeline_and_fact_retrieval_preserve_real_rls(pg):
    from verisoc.evidence.registry import EvidenceRegistry
    from verisoc.investigation.evidence_pipeline import FactRouter, investigate_evidence

    with pg.scope(demo_tenant("demo-a")) as repo:
        case = repo.list_cases()[0]
        report = investigate_evidence(repo, case)
        assert report.verified_observations
        fid = report.verified_observations[0].fact_id
    with pg.scope(demo_tenant("demo-b")) as repo:
        own_case = repo.list_cases()[0]
        with pytest.raises(NotFound):
            FactRouter(EvidenceRegistry(repo, own_case)).get(fid)
        with pytest.raises(NotFound):
            investigate_evidence(repo, case)
