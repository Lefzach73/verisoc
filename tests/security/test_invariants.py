import ast
import json
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError
from sqlalchemy import select, update

from verisoc.api.auth import Auth
from verisoc.api.main import create_app
from verisoc.core.errors import BudgetExceeded, NotFound, Unauthorized
from verisoc.core.ids import demo_tenant, stable_id
from verisoc.core.models import (
    CandidateClaim,
    CandidateReport,
    Case,
    PredicateArgs,
    RawEvent,
    VerifiedClaim,
)
from verisoc.detection.rules import detect
from verisoc.investigation.tool_router import TOOL_SCHEMAS, ToolRouter
from verisoc.llm.mock import observed, propose
from verisoc.reporting.assemble import assemble
from verisoc.reporting.render import render
from verisoc.storage.models import events
from verisoc.verification.verifier import verify

ROOT = Path(__file__).resolve().parents[2]
KEY = "synthetic-test-signing-key-32-bytes-minimum"


def token(tenant="demo-a", **overrides):
    now = datetime.now(UTC)
    payload = dict(
        sub="synthetic-researcher",
        tenant_id=str(demo_tenant(tenant)),
        iss="verisoc-research",
        aud="verisoc-api",
        iat=now,
        nbf=now,
        exp=now + timedelta(minutes=5),
    )
    payload.update(overrides)
    return jwt.encode(payload, KEY, algorithm="HS256")


def a_case(repo):
    return next(c for c in detect(repo, "demo") if c.alert.rule_id == "auth_success_after_failures")


def full_case(repo):
    records = repo.list_events("demo")[:20]
    case = Case(
        case_id=stable_id(repo.tenant, "full-test"),
        tenant_id=repo.tenant,
        dataset_id="demo",
        event_ids=tuple(e.event_id for e in records),
        start_at=records[0].occurred_at,
        end_at=records[-1].occurred_at,
    )
    repo.put_case(case)
    return case


def test_01_foreign_ids_and_exports_concealed(db):
    with db.scope(demo_tenant("demo-b")) as repo:
        case = a_case(repo)
        assemble(repo, case, propose(case, [repo.get_event(e) for e in case.event_ids]))
    with db.scope(demo_tenant("demo-a")) as repo:
        for method, value in (
            (repo.get_event, case.event_ids[0]),
            (repo.get_case, case.case_id),
            (repo.get_report, case.case_id),
            (repo.get_event, uuid4()),
        ):
            with pytest.raises(NotFound, match="Record unavailable"):
                method(value)
        assert repo.list_events("foreign-dataset") == []


def test_02_tool_tenant_arguments_foreign_search_and_no_cache(db):
    with db.scope(demo_tenant("demo-b")) as repo:
        foreign = a_case(repo)
    with db.scope(demo_tenant("demo-a")) as repo:
        case = a_case(repo)
        router = ToolRouter(repo, case)
        with pytest.raises(ValidationError):
            router.execute(
                "get_case", {"case_id": str(case.case_id), "tenant_id": str(foreign.tenant_id)}
            )
        with pytest.raises(NotFound):
            router.execute("get_case", {"case_id": str(foreign.case_id)})
        with pytest.raises(NotFound):
            router.execute("get_evidence", {"event_ids": [str(foreign.event_ids[0])]})
        result = router.execute(
            "search_events",
            dict(
                case_id=str(case.case_id),
                start=case.start_at.isoformat(),
                end=case.end_at.isoformat(),
            ),
        )
        assert set(r["event_id"] for r in result).issubset(set(map(str, case.event_ids)))
        assert not any("tenant_id" in row for row in result)
        assert not hasattr(router, "cache")


def test_03_authentication_and_tenant_impersonation(db):
    client = TestClient(create_app(db, Auth(KEY)))
    for headers in (
        {},
        {"X-Tenant-ID": str(demo_tenant("demo-a"))},
        {"Authorization": "Bearer malformed"},
        {"Authorization": "Bearer " + token(aud="wrong")},
        {"Authorization": "Bearer " + token(exp=0)},
        {"Authorization": "Bearer " + token(tenant_id="invalid")},
    ):
        assert client.get("/v1/cases", headers=headers).status_code == 401
    headers = {"Authorization": "Bearer " + token(), "X-Tenant-ID": str(demo_tenant("demo-b"))}
    assert (
        client.post("/v1/cases/detect", json={"dataset_id": "demo"}, headers=headers).status_code
        == 200
    )
    cases = client.get("/v1/cases", headers=headers).json()
    assert cases and all(c["tenant_id"] == str(demo_tenant("demo-a")) for c in cases)
    bad = client.post(
        "/v1/cases/detect", json={"dataset_id": "demo", "tenant_id": "demo-b"}, headers=headers
    )
    assert bad.status_code == 422 and bad.json() == {"error": "invalid_request"}


def test_04_existing_citation_is_not_proof(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = full_case(repo)
        event = repo.get_event(case.event_ids[-1])
        wrong = observed(event).model_copy(
            update={"parameters": PredicateArgs(process_name="fabricated.exe")}
        )
        decision = verify(repo, case, wrong)
        assert decision.status == "rejected" and decision.reason_code == "predicate_mismatch"


def test_05_missing_conflicting_unknown_claims(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = a_case(repo)
        for ids in ((), (uuid4(),)):
            claim = CandidateClaim(
                claim_id=uuid4(), claim_kind="observed_login_failure", subject_event_ids=ids
            )
            assert verify(repo, case, claim).status != "verified"
        with pytest.raises(ValidationError):
            CandidateClaim(claim_id=uuid4(), claim_kind="unknown", subject_event_ids=())
        claim = observed(repo.get_event(case.event_ids[0])).model_copy(
            update={"parameters": PredicateArgs(user_id="conflict")}
        )
        assert verify(repo, case, claim).status == "rejected"


def test_06_inference_never_verified_or_minted_from_json(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = a_case(repo)
        claim = CandidateClaim(
            claim_id=uuid4(),
            claim_kind="analyst_inference",
            subject_event_ids=case.event_ids[:1],
            explanation="this is certainly an attacker",
        )
        decision = verify(repo, case, claim)
        assert decision.status == "insufficient"
        with pytest.raises(ValidationError):
            VerifiedClaim.model_validate_json(decision.model_dump_json())
        with pytest.raises(ValidationError):
            CandidateReport.model_validate(
                {
                    "claims": [dict(claim.model_dump(), status="verified")],
                    "proposed_verdict": "malicious",
                }
            )
        report = assemble(
            repo, case, CandidateReport(claims=(claim,), proposed_verdict="malicious")
        )
        assert report.verdict == "needs_review" and "UNVERIFIED HYPOTHESIS" in render(report)


def test_07_inert_injection_and_unauthorized_tool(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        injection = next(
            e
            for e in repo.list_events("demo")
            if "ignore previous instructions" in e.attributes.message
        )
        assert "synthetic-secret" not in injection.attributes.message
        case = next(c for c in detect(repo, "demo") if injection.event_id in c.event_ids)
        router = ToolRouter(repo, case)
        output = router.execute("get_evidence", {"event_ids": [str(injection.event_id)]})
        assert "ignore previous" not in json.dumps(output)
        for name in ("shell", "http", "scan", "cloud", "reveal_system_prompt"):
            with pytest.raises(Unauthorized):
                router.execute(name, {})
        assert router.trace[0] == {"tool": "get_evidence", "call": 1, "result_count": 1}
        assert len(router.trace) == 6
        assert all(t.get("status") == "rejected" for t in router.trace[1:])


def test_08_bounded_tools_and_malformed_output(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = a_case(repo)
        router = ToolRouter(repo, case, max_calls=1)
        router.execute("get_case", {"case_id": str(case.case_id)})
        with pytest.raises(BudgetExceeded):
            router.execute("get_case", {"case_id": str(case.case_id)})
        with pytest.raises(ValidationError):
            CandidateReport.model_validate_json('{"claims":[]')
        with pytest.raises(ValidationError):
            ToolRouter(repo, case).execute("get_evidence", {"event_ids": [str(uuid4())] * 65})


def test_09_out_of_order_preserves_chronology(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        reverse = next(
            c
            for c in detect(repo, "demo")
            if c.start_at.day == 8 and c.alert.rule_id == "auth_success_after_failures"
        )
        records = [repo.get_event(e) for e in reverse.event_ids]
        assert records == sorted(records, key=lambda e: (e.occurred_at, str(e.event_id)))
        assert reverse.case_id in {c.case_id for c in detect(repo, "demo")}


def test_10_runtime_cannot_import_labels():
    for path in (ROOT / "src/verisoc").rglob("*.py"):
        if "/evaluation/" in str(path) or path.name == "cli.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom):
                assert "evaluation" not in (node.module or "")
            if isinstance(node, ast.Import):
                assert all("evaluation" not in a.name for a in node.names)
        assert (
            "cases.jsonl" not in path.read_text()
            and "expected_evidence.jsonl" not in path.read_text()
        )


def test_11_emitted_verified_evidence_traceable(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        for case in detect(repo, "demo"):
            report = assemble(
                repo, case, propose(case, [repo.get_event(e) for e in case.event_ids])
            )
            for decision in report.verified_claims:
                assert (
                    decision.supporting_event_ids
                    and verify(repo, case, decision.candidate).status == "verified"
                )
                assert all(
                    repo.provenance_ok(repo.get_event(e)) for e in decision.supporting_event_ids
                )


def test_12_canonical_byte_change_rejected(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = a_case(repo)
        claim = observed(repo.get_event(case.event_ids[0]))
        predicate = (events.c.tenant_id == str(repo.tenant)) & (
            events.c.event_id == str(case.event_ids[0])
        )
        data = repo.conn.execute(select(events.c.data).where(predicate)).scalar_one()
        data["host_id"] += "x"
        repo.conn.execute(update(events).where(predicate).values(data=data))
        decision = verify(repo, case, claim)
        assert decision.status == "rejected" and decision.reason_code == "provenance_mismatch"


def test_13_tool_inventory_has_no_execution():
    assert set(TOOL_SCHEMAS) == {
        "get_case",
        "search_events",
        "get_related",
        "get_evidence",
        "submit_candidate_report",
    }
    for schema in TOOL_SCHEMAS.values():
        assert not {"tenant_id", "sql", "url", "command"}.intersection(schema.model_fields)


def test_14_api_offline_end_to_end(db, monkeypatch):
    monkeypatch.setattr(
        socket.socket, "connect", lambda *a, **k: pytest.fail("external socket call")
    )
    client = TestClient(create_app(db, Auth(KEY)))
    headers = {"Authorization": "Bearer " + token()}
    assert client.get("/healthz").status_code == 200
    response = client.post(
        "/v1/events/import",
        headers=headers,
        json={
            "dataset_id": "api-test",
            "jsonl": json.dumps(
                dict(event_code=4688, timestamp="2026-01-01T00:00:00Z", process="lab-indicator.exe")
            ),
        },
    )
    assert response.status_code == 200
    detected = client.post(
        "/v1/cases/detect", headers=headers, json={"dataset_id": "api-test"}
    ).json()
    cid = detected[0]["case_id"]
    report = client.post(f"/v1/cases/{cid}/investigate", headers=headers)
    assert report.status_code == 200 and report.json()["verdict"] == "needs_review"
    assert client.get(f"/v1/cases/{cid}/report", headers=headers).json() == report.json()
    foreign = {"Authorization": "Bearer " + token("demo-b")}
    assert client.get(f"/v1/cases/{cid}", headers=foreign).json() == {"error": "not_found"}
    assert client.get(f"/v1/cases/{cid}/report", headers=foreign).status_code == 404


@given(st.uuids(), st.integers(min_value=-86400, max_value=86400))
@settings(max_examples=50)
def test_tenant_uuid_and_utc_property(tenant, offset):
    assert Auth(KEY).tenant("Bearer " + token(tenant_id=str(tenant))) == tenant
    instant = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=offset)
    assert RawEvent(event_code=4625, timestamp=instant.isoformat()).timestamp == instant


def test_stored_report_rechecks_tampered_evidence_and_narrative(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = a_case(repo)
        event = repo.get_event(case.event_ids[0])
        claim = observed(event).model_copy(
            update={"explanation": "SECRET malicious narrative is not proof"}
        )
        report = assemble(
            repo, case, CandidateReport(claims=(claim,), proposed_verdict="malicious")
        )
        assert "SECRET" not in report.model_dump_json()
        predicate = (events.c.tenant_id == str(repo.tenant)) & (
            events.c.event_id == str(event.event_id)
        )
        data = repo.conn.execute(select(events.c.data).where(predicate)).scalar_one()
        data["host_id"] += "x"
        repo.conn.execute(update(events).where(predicate).values(data=data))
        changed = repo.get_report(case.case_id)
        assert changed.verdict == "needs_review" and not changed.verified_claims
        assert "stored_evidence_changed" in changed.limit_reasons


def test_api_size_and_rate_limits_are_explicit_and_tenant_scoped(db, monkeypatch):
    from verisoc.api.main import RateLimiter

    original = RateLimiter.__init__
    monkeypatch.setattr(RateLimiter, "__init__", lambda self: original(self, cap=1))
    client = TestClient(create_app(db, Auth(KEY)))
    headers = {"Authorization": "Bearer " + token()}
    assert (
        client.post("/v1/cases/detect", headers=headers, json={"dataset_id": "demo"}).status_code
        == 200
    )
    limited = client.post("/v1/cases/detect", headers=headers, json={"dataset_id": "demo"})
    assert limited.status_code == 429 and limited.json() == {"error": "rate_limited"}
    assert (
        client.post(
            "/v1/cases/detect",
            headers={"Authorization": "Bearer " + token("demo-b")},
            json={"dataset_id": "demo"},
        ).status_code
        == 200
    )
    assert (
        client.post("/v1/events/import", headers=headers, content=b"x" * 1200000).status_code == 413
    )
