import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from verisoc.core.errors import Conflict
from verisoc.core.ids import demo_tenant
from verisoc.core.models import RawEvent
from verisoc.detection.rules import detect
from verisoc.ingest.importer import import_jsonl
from verisoc.llm.mock import propose
from verisoc.reporting.assemble import assemble
from verisoc.verification.verifier import verify

ROOT = Path(__file__).resolve().parents[2]


def test_real_slice(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        cases = detect(repo, "demo")
        assert {c.alert.rule_id for c in cases} == {
            "auth_burst",
            "auth_success_after_failures",
            "lab_process",
        }
        case = next(c for c in cases if c.alert.rule_id == "auth_burst")
        events = [repo.get_event(e) for e in case.event_ids]
        proposal = propose(case, events)
        assert verify(repo, case, proposal.claims[0]).status == "verified"
        assert verify(repo, case, proposal.claims[1]).status == "rejected"
        report = assemble(repo, case, proposal)
        assert report.verdict == "needs_review"
        assert len(report.verified_claims) == 1
        assert all(repo.provenance_ok(repo.get_event(e)) for e in report.evidence_refs)


def test_import_idempotency_and_conflict(db):
    content = (ROOT / "fixtures/demo/events.jsonl").read_bytes()
    with db.scope(demo_tenant("demo-a")) as repo:
        m = import_jsonl(repo, content, "demo", fixture_tenant="demo-a")
        assert m.accepted == 0
        assert len(m.event_ids) == 236
        assert m.duplicates == 240
    with pytest.raises(Conflict), db.scope(demo_tenant("demo-a")) as repo:
        import_jsonl(
            repo,
            content.replace(b"explorer.exe", b"different.exe"),
            "demo",
            fixture_tenant="demo-a",
        )


def test_schema_times_and_ips():
    event = RawEvent(event_code=4625, timestamp="2026-01-01T05:00:00+05:00")
    assert event.timestamp == datetime(2026, 1, 1, tzinfo=UTC)
    for fields in (
        {"timestamp": "2026-01-01"},
        {"src_ip": "999.0.0.1"},
        {"dst_port": -1},
        {"tenant_id": "forged"},
    ):
        with pytest.raises(ValidationError):
            RawEvent.model_validate(dict(event.model_dump(), **fields))


def test_explicit_scenarios_and_annotations(db):
    labels = [
        json.loads(line) for line in (ROOT / "fixtures/demo/cases.jsonl").read_text().splitlines()
    ]
    assert len(labels) == 24
    assert len({c["family"] for c in labels}) == 6
    for tenant in ("demo-a", "demo-b"):
        with db.scope(demo_tenant(tenant)) as repo:
            cases = detect(repo, "demo")
            events = repo.list_events("demo")
            for label in (c for c in labels if c["tenant"] == tenant):
                subset = [
                    e
                    for e in events
                    if label["start_at"] <= e.occurred_at.isoformat() <= label["end_at"]
                ]
                assert len(subset) == (16 if label["scenario_type"] == "duplicate_delivery" else 20)
                rules = {
                    c.alert.rule_id
                    for c in cases
                    if label["start_at"] <= c.start_at.isoformat() <= label["end_at"]
                }
                if label["expected_rule"]:
                    assert label["expected_rule"] in rules
                else:
                    assert not rules
