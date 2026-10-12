import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import update

from verisoc.api.auth import Auth
from verisoc.api.main import create_app
from verisoc.core.errors import BudgetExceeded, NotFound
from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect
from verisoc.evidence.registry import EvidenceRegistry
from verisoc.investigation.evidence_pipeline import (
    MAX_PACKET_BYTES,
    CaseWindow,
    FactRouter,
    FactSelection,
    investigate_evidence,
    open_window,
    render_evidence,
)
from verisoc.storage.models import events


class Select:
    def __init__(self, fn):
        self.fn = fn

    def select(self, packet, router):
        return self.fn(packet, router)


def test_mock_separates_verified_indicators_from_intent(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
        report = investigate_evidence(repo, case)
        assert report.verified_observations and report.source_proofs
        assert report.incident_verdict == "needs_review"
        assert report.risk_assessment == "suspicious"
        assert report == investigate_evidence(repo, case)
        assert "src_ip" not in render_evidence(report)


@pytest.mark.parametrize("mutation", ["invented_predicate", "foreign_id", "duplicate_id", "huge"])
def test_selection_is_bounded_ids_only(db, mutation):
    def select(packet, router):
        data = dict(fact_ids=[str(packet.facts[0].fact_id)])
        if mutation == "invented_predicate":
            data["predicate"] = "confirmed_attack"
        if mutation == "foreign_id":
            data["fact_ids"] = [str(uuid4())]
        if mutation == "duplicate_id":
            data["fact_ids"] *= 2
        if mutation == "huge":
            return " " * (MAX_PACKET_BYTES + 1)
        return json.dumps(data)

    with db.scope(demo_tenant("demo-a")) as repo:
        report = investigate_evidence(repo, detect(repo, "demo")[0], Select(select))
        assert not report.verified_observations
        assert report.confidence_or_abstention_reason == ("invalid_selection",)


def test_final_check_detects_source_change_after_selection(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]

        def mutate(packet, router):
            eid = packet.facts[0].source_event_ids[0]
            data = repo.get_event(eid).model_dump(mode="json")
            data["process_name"] = "changed-after-packet.exe"
            repo.conn.execute(
                update(events)
                .where(events.c.tenant_id == str(repo.tenant), events.c.event_id == str(eid))
                .values(data=data)
            )
            return FactSelection(fact_ids=(packet.facts[0].fact_id,)).model_dump_json()

        report = investigate_evidence(repo, case, Select(mutate))
        assert not report.verified_observations
        assert report.confidence_or_abstention_reason == ("verifier_rejected",)


def test_read_only_router_budget_tenant_and_packet_bounds(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        registry = EvidenceRegistry(repo, detect(repo, "demo")[0])
        router = FactRouter(registry, maximum_calls=2)
        packet = router.packet(limit=1)
        assert len(packet.facts) == 1 and packet.omitted > 0
        assert len(packet.model_dump_json().encode()) <= MAX_PACKET_BYTES
        with pytest.raises(NotFound):
            router.get(uuid4())
        with pytest.raises(BudgetExceeded):
            router.packet()
        with pytest.raises(ValueError):
            FactRouter(registry).packet(offset=-1)
        with pytest.raises(ValueError):
            FactRouter(registry).packet(limit=33)


def test_untrusted_interpretation_is_escaped_and_never_verified(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        selector = Select(
            lambda p, r: FactSelection(
                fact_ids=(p.facts[0].fact_id,), observation="<script>alert(1)</script>\x1b"
            ).model_dump_json()
        )
        report = investigate_evidence(repo, detect(repo, "demo")[0], selector)
        assert (
            "<script>" not in render_evidence(report) and "\x1b" not in report.risk_interpretation
        )
        assert report.interpretation_status == "unverified_analyst_text"
        assert report.incident_verdict == "needs_review"


def test_provider_failure_is_sanitized_and_explicit(db):
    def fail(packet, router):
        raise RuntimeError("private-source-should-not-leak")

    with db.scope(demo_tenant("demo-a")) as repo:
        report = investigate_evidence(repo, detect(repo, "demo")[0], Select(fail))
        assert report.confidence_or_abstention_reason == ("provider_failure",)
        assert "private-source" not in render_evidence(report)


def test_model_uncertainty_does_not_turn_into_confirmed_intent(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        selector = Select(
            lambda p, r: FactSelection(
                fact_ids=(p.facts[0].fact_id,), abstention_reason="model_uncertainty"
            ).model_dump_json()
        )
        report = investigate_evidence(repo, detect(repo, "demo")[0], selector)
        assert report.verified_observations
        assert report.risk_assessment == "insufficient_evidence"
        assert "model_uncertainty" in report.confidence_or_abstention_reason


def test_open_window_is_scoped_bounded_and_no_signal_is_not_benign(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        event = next(e for e in repo.list_events("demo") if e.attributes.event_code == 3)
        case = open_window(
            repo,
            CaseWindow(dataset_id="demo", start_at=event.occurred_at, end_at=event.occurred_at),
        )
        report = investigate_evidence(repo, case)
        assert report.risk_assessment == "insufficient_evidence"
        assert "no_signal" in report.confidence_or_abstention_reason
        with pytest.raises(ValueError):
            open_window(
                repo,
                CaseWindow(
                    start_at=event.occurred_at, end_at=event.occurred_at + timedelta(days=2)
                ),
            )
        with pytest.raises(ValidationError):
            CaseWindow(start_at="2027-01-01", end_at="2027-01-02")


def test_new_api_auth_and_cross_tenant_resources(db):
    secret = "synthetic-v04-api-test-key-at-least-32-bytes"
    app = create_app(db, Auth(secret))
    client = TestClient(app)

    def headers(name):
        now = datetime.now(UTC)
        return {
            "Authorization": "Bearer "
            + jwt.encode(
                dict(
                    tenant_id=str(demo_tenant(name)),
                    sub="test",
                    iat=now,
                    nbf=now,
                    exp=now + timedelta(minutes=5),
                    iss="verisoc-research",
                    aud="verisoc-api",
                ),
                secret,
                algorithm="HS256",
            )
        }

    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
    url = f"/v1/cases/{case.case_id}"
    assert client.get(url + "/facts").status_code == 401
    assert client.get(url + "/facts", headers=headers("demo-b")).status_code == 404
    packet = client.get(url + "/facts", headers=headers("demo-a"))
    assert packet.status_code == 200
    fid = packet.json()["facts"][0]["fact_id"]
    assert client.get(url + "/facts/" + fid, headers=headers("demo-b")).status_code == 404
    assert client.get(url + "/facts/" + fid, headers=headers("demo-a")).status_code == 200
    assert client.get(url + "/facts/" + str(uuid4()), headers=headers("demo-a")).status_code == 404
    report = client.post(url + "/investigate-v04", headers=headers("demo-a"))
    assert report.status_code == 200 and report.json()["incident_verdict"] == "needs_review"
    opened = client.post(
        "/v1/evidence/cases",
        headers=headers("demo-a"),
        json=dict(
            dataset_id="demo", start_at=case.start_at.isoformat(), end_at=case.end_at.isoformat()
        ),
    )
    assert opened.status_code == 200


def test_existing_but_unoffered_fact_id_is_rejected(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = large_packet_case(repo)
        registry = EvidenceRegistry(repo, case)

        def hidden(packet, router):
            unoffered = next(fid for fid in registry.facts if fid not in router.offered)
            return FactSelection(fact_ids=(unoffered,)).model_dump_json()

        report = investigate_evidence(repo, case, Select(hidden))
        assert report.confidence_or_abstention_reason == ("invalid_selection",)
        assert not report.verified_observations


def test_background_truncation_does_not_remove_valid_selected_indicator(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = large_packet_case(repo)
        report = investigate_evidence(repo, case)
        assert "context_truncated" in report.confidence_or_abstention_reason
        assert report.risk_assessment == "suspicious"
        assert report.incident_verdict == "needs_review"
        assert len(report.verified_observations) <= 32


def large_packet_case(repo):
    from verisoc.ingest.importer import import_jsonl

    start = datetime(2027, 3, 1, tzinfo=UTC)
    rows = [
        dict(
            event_code=4688,
            timestamp=start.isoformat(),
            host="bounded-host",
            process="lab-indicator.exe",
        )
    ]
    rows.extend(
        dict(
            event_code=3,
            timestamp=(start + timedelta(seconds=i)).isoformat(),
            host="bounded-host",
            dst_port=443,
        )
        for i in range(1, 51)
    )
    content = ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
    import_jsonl(repo, content, "packet-test")
    return open_window(
        repo,
        CaseWindow(dataset_id="packet-test", start_at=start, end_at=start + timedelta(seconds=50)),
    )
