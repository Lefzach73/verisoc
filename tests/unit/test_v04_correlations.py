import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from verisoc.core.ids import demo_tenant, stable_id
from verisoc.core.models import Case
from verisoc.evidence.models import FactCandidate, fact_identity
from verisoc.evidence.registry import EvidenceRegistry
from verisoc.evidence.rules import require_capability
from verisoc.ingest.importer import import_jsonl
from verisoc.storage.repository import Database
from verisoc.verification.facts import verify_fact

START = datetime(2027, 1, 1, tzinfo=UTC)


def event(code, seconds, **extra):
    return dict(
        event_code=code,
        timestamp=(START + timedelta(seconds=seconds)).isoformat(),
        host="host",
        user="user",
        **extra,
    )


def failures(n=5):
    return [event(4625, i * 10) for i in range(n)]


@contextmanager
def scenario(rows):
    db = Database("sqlite:///:memory:")
    try:
        with db.scope(demo_tenant("demo-a")) as repo:
            import_jsonl(repo, ("\n".join(json.dumps(r) for r in rows) + "\n").encode(), "dev")
            records = repo.list_events("dev")
            case = Case(
                case_id=stable_id("v04-dev-case"),
                tenant_id=repo.tenant,
                dataset_id="dev",
                event_ids=tuple(e.event_id for e in records),
                start_at=records[0].occurred_at,
                end_at=records[-1].occurred_at,
            )
            repo.put_case(case)
            registry = EvidenceRegistry(repo, case)
            assert not registry.rejections
            yield repo, case, registry
    finally:
        db.engine.dispose()


@pytest.mark.parametrize(
    "success_time,expected", [(50, True), (300, True), (301, False), (-1, False), (0, False)]
)
def test_ordered_auth_has_strict_event_time_and_bounded_window(success_time, expected):
    with scenario(failures() + [event(4624, success_time)]) as (_, _, registry):
        assert (
            any(f.predicate == "success_after_failures" for f in registry.facts.values())
            is expected
        )


@pytest.mark.parametrize("field", ["host", "user"])
def test_success_never_joins_another_actor_or_host(field):
    success = event(4624, 50)
    success[field] = "different"
    with scenario(failures() + [success]) as (_, _, registry):
        assert not any(f.predicate == "success_after_failures" for f in registry.facts.values())


def test_duplicates_do_not_inflate_aggregate():
    rows = failures(4)
    with scenario(rows + [rows[0], rows[0]]) as (_, _, registry):
        assert all(f.predicate == "observed_event" for f in registry.facts.values())


def test_value_count_and_source_grouping_are_distinct():
    rows = failures(6)
    for i, row in enumerate(rows):
        row.update(user=f"account-{i}", src_ip="192.0.2.1" if i < 3 else "192.0.2.2")
    with scenario(rows) as (_, _, registry):
        predicates = {f.predicate for f in registry.facts.values()}
        assert "multi_account_failures" in predicates
        assert "source_account_failures" not in predicates
    for row in rows:
        row["src_ip"] = "192.0.2.1"
    with scenario(rows) as (_, _, registry):
        assert any(
            f.predicate == "source_account_failures" and f.arguments.distinct_users == 6
            for f in registry.facts.values()
        )


def test_missing_identifiers_do_not_create_actor_correlations():
    rows = failures(6)
    for row in rows:
        row["user"] = None
    with scenario(rows) as (_, _, registry):
        assert all(f.predicate == "observed_event" for f in registry.facts.values())


@pytest.mark.parametrize(
    "name,expected",
    [
        ("LAB-INDICATOR.EXE", True),
        ("C:\\Windows\\lab-indicator.exe", True),
        ("lab-indicator.exe.backup", False),
        ("normal.exe", False),
    ],
)
def test_windows_basename_semantics_do_not_claim_executable_identity(name, expected):
    with scenario([event(4688, 0, process=name)]) as (_, _, registry):
        assert (
            any(f.predicate == "windows_image_match" for f in registry.facts.values()) is expected
        )


@pytest.mark.parametrize("mutation", ["count", "membership", "window", "join", "distinct"])
def test_recomputed_aggregation_rejects_re_signed_mistakes(mutation):
    rows = failures(6)
    for i, row in enumerate(rows):
        row["user"] = f"account-{i}"
    with scenario(rows) as (repo, case, registry):
        fact = next(f for f in registry.facts.values() if f.predicate == "multi_account_failures")
        data = fact.model_dump(mode="json", exclude={"verification_status"})
        if mutation == "count":
            data["arguments"]["event_count"] = 5
        elif mutation == "membership":
            data["source_event_ids"].pop()
            data["evidence_hashes"].pop()
            data["arguments"]["event_count"] = 5
            data["arguments"]["distinct_users"] = 5
        elif mutation == "window":
            data["arguments"]["start_at"] = (START + timedelta(seconds=1)).isoformat()
        elif mutation == "join":
            data["arguments"]["host_id"] = "other-host"
        else:
            data["arguments"]["distinct_users"] = 5
        data["fact_id"] = str(fact_identity(data))
        assert verify_fact(repo, case, FactCandidate.model_validate(data)).status == "rejected"


def test_backend_does_not_claim_unimplemented_sigma_capabilities():
    require_capability("event_count")
    require_capability("value_count")
    require_capability("temporal_ordered")
    for kind in ("temporal", "value_sum", "arbitrary_script"):
        with pytest.raises(ValueError):
            require_capability(kind)
    with pytest.raises(ValueError):
        require_capability("event_count", "unconfigured-external-backend")


def test_overflow_is_rejected_without_silent_truncation():
    from verisoc.core.errors import BudgetExceeded
    from verisoc.investigation.evidence_pipeline import CaseWindow, open_window

    db = Database("sqlite:///:memory:")
    try:
        with db.scope(demo_tenant("demo-a")) as repo:
            rows = [event(3, i, dst_port=443) for i in range(501)]
            import_jsonl(repo, ("\n".join(json.dumps(r) for r in rows) + "\n").encode(), "dev")
            with pytest.raises(BudgetExceeded):
                open_window(
                    repo,
                    CaseWindow(
                        dataset_id="dev", start_at=START, end_at=START + timedelta(seconds=500)
                    ),
                )
    finally:
        db.engine.dispose()
