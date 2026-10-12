import pytest

from verisoc.core.ids import demo_tenant
from verisoc.ingest.importer import import_jsonl
from verisoc.storage.repository import Database


def test_duplicate_json_fields_rejected_atomically():
    db = Database("sqlite:///:memory:")
    content = (
        b'{"event_code":4625,"timestamp":"2026-01-01T00:00:00Z"}\n'
        b'{"event_code":4624,"event_code":4625,"timestamp":"2026-01-01T00:01:00Z"}\n'
    )
    with db.scope(demo_tenant("demo-a")) as repo:
        with pytest.raises(ValueError, match="Duplicate JSON field"):
            import_jsonl(repo, content, "ambiguous")
        assert repo.list_events("ambiguous") == []
    db.engine.dispose()


def test_numeric_epoch_is_not_silently_admitted_as_rfc3339():
    db = Database("sqlite:///:memory:")
    with db.scope(demo_tenant("demo-a")) as repo:
        with pytest.raises(ValueError):
            import_jsonl(repo, b'{"event_code":4625,"timestamp":1}', "bad-time")
        assert repo.list_events("bad-time") == []
    db.engine.dispose()
