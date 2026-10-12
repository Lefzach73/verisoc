import pytest
from sqlalchemy import select, update

from verisoc.core.errors import NotFound
from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect
from verisoc.llm.mock import propose
from verisoc.reporting.assemble import assemble
from verisoc.storage.models import cases, events, reports


def test_event_lookup_rejects_valid_record_swapped_under_another_id(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        records = repo.list_events("demo")
        first, second = records[0], records[-1]
        repo.conn.execute(
            update(events)
            .where(events.c.tenant_id == str(repo.tenant), events.c.event_id == str(first.event_id))
            .values(data=second.model_dump(mode="json"))
        )
        with pytest.raises(NotFound, match="Record unavailable"):
            repo.get_event(first.event_id)


def test_event_search_rejects_column_payload_scope_mismatch(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        record = repo.list_events("demo")[0]
        repo.conn.execute(
            update(events)
            .where(
                events.c.tenant_id == str(repo.tenant), events.c.event_id == str(record.event_id)
            )
            .values(dataset_id="forged-index")
        )
        with pytest.raises(NotFound, match="Record unavailable"):
            repo.list_events("forged-index")


def test_case_lookup_and_list_reject_substituted_case_payload(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        first, second = detect(repo, "demo")[:2]
        repo.conn.execute(
            update(cases)
            .where(cases.c.tenant_id == str(repo.tenant), cases.c.case_id == str(first.case_id))
            .values(data=second.model_dump(mode="json"))
        )
        with pytest.raises(NotFound, match="Record unavailable"):
            repo.get_case(first.case_id)
        with pytest.raises(NotFound, match="Record unavailable"):
            repo.list_cases()


def test_report_lookup_rejects_substituted_report_payload(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        first, second = detect(repo, "demo")[:2]
        for case in (first, second):
            assemble(repo, case, propose(case, [repo.get_event(e) for e in case.event_ids]))
        data = repo.conn.execute(
            select(reports.c.data).where(
                reports.c.tenant_id == str(repo.tenant), reports.c.case_id == str(second.case_id)
            )
        ).scalar_one()
        repo.conn.execute(
            update(reports)
            .where(reports.c.tenant_id == str(repo.tenant), reports.c.case_id == str(first.case_id))
            .values(data=data)
        )
        with pytest.raises(NotFound, match="Record unavailable"):
            repo.get_report(first.case_id)


def test_report_rebuilds_support_ids_and_neutral_text_from_verified_candidates(db):
    with db.scope(demo_tenant("demo-b")) as repo:
        foreign = repo.list_events("demo")[0].event_id
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
        original = assemble(repo, case, propose(case, [repo.get_event(e) for e in case.event_ids]))
        data = original.model_dump(mode="json")
        data["verified_claims"][0]["supporting_event_ids"] = [str(foreign)]
        data["verified_claims"][0]["candidate"]["explanation"] = "FABRICATED VERIFIED NARRATIVE"
        data["evidence_refs"] = [str(foreign)]
        repo.conn.execute(
            update(reports)
            .where(reports.c.tenant_id == str(repo.tenant), reports.c.case_id == str(case.case_id))
            .values(data=data)
        )
        exported = repo.get_report(case.case_id)
        assert foreign not in exported.evidence_refs
        assert "FABRICATED VERIFIED NARRATIVE" not in exported.model_dump_json()
        assert exported.limit_reasons and exported.verdict == "needs_review"


@pytest.mark.parametrize("forged_verdict", ["malicious", "benign"])
def test_stored_verdict_cannot_bypass_evidence_policy(db, forged_verdict):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = next(c for c in detect(repo, "demo") if c.alert.rule_id == "auth_burst")
        report = assemble(repo, case, propose(case, [repo.get_event(e) for e in case.event_ids]))
        data = report.model_dump(mode="json")
        data["verdict"] = forged_verdict
        data["missing_evidence"] = []
        repo.conn.execute(
            update(reports)
            .where(reports.c.tenant_id == str(repo.tenant), reports.c.case_id == str(case.case_id))
            .values(data=data)
        )
        assert repo.get_report(case.case_id).verdict == "needs_review"


def test_stored_evidence_details_are_rebuilt_not_trusted(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
        report = assemble(repo, case, propose(case, [repo.get_event(e) for e in case.event_ids]))
        data = report.model_dump(mode="json")
        data["evidence_details"][0]["process_name"] = "FORGED-DETAIL"
        repo.conn.execute(
            update(reports)
            .where(reports.c.tenant_id == str(repo.tenant), reports.c.case_id == str(case.case_id))
            .values(data=data)
        )
        exported = repo.get_report(case.case_id)
        assert "FORGED-DETAIL" not in exported.model_dump_json()
        assert exported.verdict == "needs_review"
