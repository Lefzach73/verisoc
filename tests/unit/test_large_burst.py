import json
from datetime import UTC, datetime, timedelta

import pytest

from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect, qualified_signal
from verisoc.ingest.importer import import_jsonl
from verisoc.storage.repository import Database


@pytest.mark.parametrize("equal_time", [False, True])
def test_dense_auth_burst_stays_within_evidence_contract(equal_time):
    db = Database("sqlite:///:memory:")
    start = datetime(2026, 3, 1, tzinfo=UTC)
    rows = [
        dict(
            event_code=4625,
            timestamp=(start + timedelta(milliseconds=0 if equal_time else i)).isoformat(),
            host="host",
            user="user",
            message=f"synthetic failure {i}",
        )
        for i in range(600)
    ]
    rows.append(
        dict(
            event_code=4624,
            timestamp=(start + timedelta(seconds=10)).isoformat(),
            host="host",
            user="user",
        )
    )
    content = ("\n".join(json.dumps(r) for r in rows) + "\n").encode()
    with db.scope(demo_tenant("demo-a")) as repo:
        assert import_jsonl(repo, content, "dense").accepted == 601
        result = detect(repo, "dense")
        assert result and all(len(c.event_ids) <= 500 for c in result)
        successes = [c for c in result if c.alert.rule_id == "auth_success_after_failures"]
        assert len(successes) == 1
        assert qualified_signal(successes[0], [repo.get_event(e) for e in successes[0].event_ids])
    db.engine.dispose()
