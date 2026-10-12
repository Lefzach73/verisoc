import asyncio
import json
from datetime import UTC, datetime, timedelta

from verisoc.core.ids import demo_tenant, stable_id
from verisoc.core.models import CandidateReport, Case
from verisoc.detection.rules import detect
from verisoc.ingest.importer import import_jsonl
from verisoc.investigation.pipeline import candidate
from verisoc.llm.base import Budget
from verisoc.llm.mock import MockProvider, observed
from verisoc.reporting.assemble import assemble
from verisoc.reporting.render import render
from verisoc.storage.repository import Database


def test_selected_context_contains_alert_after_first_64_events():
    database = Database("sqlite:///:memory:")
    start = datetime(2026, 5, 1, tzinfo=UTC)
    data = [
        dict(
            event_code=4688,
            timestamp=(start + timedelta(seconds=i)).isoformat(),
            host="host",
            process="lab-indicator.exe" if i == 80 else "normal.exe",
        )
        for i in range(81)
    ]
    with database.scope(demo_tenant("demo-a")) as repo:
        import_jsonl(repo, ("\n".join(json.dumps(r) for r in data) + "\n").encode(), "late")
        events = repo.list_events("late")
        alert = detect(repo, "late")[0].alert
        case = Case(
            case_id=stable_id("late-case"),
            tenant_id=repo.tenant,
            dataset_id="late",
            event_ids=tuple(e.event_id for e in events),
            start_at=start,
            end_at=events[-1].occurred_at,
            alert=alert,
        )
        repo.put_case(case)
        result = asyncio.run(candidate(repo, case, MockProvider(), Budget(max_input_tokens=65536)))
        assert str(alert.event_ids[0]) in {r["event_id"] for r in result.context}
        assert len(result.context) <= 64
    database.engine.dispose()


def test_verified_report_renders_authorized_fact_fields_and_lineage(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = next(c for c in detect(repo, "demo") if c.alert.rule_id == "lab_process")
        event = repo.get_event(case.event_ids[0])
        report = assemble(
            repo, case, CandidateReport(claims=(observed(event),), proposed_verdict="malicious")
        )
        assert report.verdict == "malicious"
        text = render(repo.get_report(case.case_id))
        assert "lab-indicator.exe" in text
        assert event.source_ref.file_sha256 in text
        assert event.occurred_at.isoformat() in text


def test_optional_hypothesis_is_separate_from_complete_verified_signal(db):
    from verisoc.core.models import CandidateClaim

    with db.scope(demo_tenant("demo-a")) as repo:
        case = next(c for c in detect(repo, "demo") if c.alert.rule_id == "lab_process")
        event = repo.get_event(case.event_ids[0])
        inference = CandidateClaim(
            claim_id=stable_id("unverified-interpretation"),
            claim_kind="analyst_inference",
            subject_event_ids=(event.event_id,),
            explanation="Possible interpretation, not proven.",
        )
        report = assemble(
            repo,
            case,
            CandidateReport(claims=(observed(event), inference), proposed_verdict="malicious"),
        )
        assert report.verdict == "malicious"
        assert len(report.verified_claims) == 1 and len(report.hypotheses) == 1
        assert repo.get_report(case.case_id).verdict == "malicious"
        without_facts = assemble(
            repo, case, CandidateReport(claims=(inference,), proposed_verdict="malicious")
        )
        assert without_facts.verdict == "needs_review"
        assert not without_facts.verified_claims


def test_report_render_escapes_html_and_terminal_controls():
    from verisoc.reporting.render import safe_text

    result = safe_text("<script>\x1b[31m\u202efake</script>")
    assert "<script>" not in result and "\x1b" not in result and "\u202e" not in result
    assert "&lt;script&gt;" in result
