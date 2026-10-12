from pathlib import Path

import pytest

from verisoc.core.ids import demo_tenant
from verisoc.ingest.importer import import_jsonl
from verisoc.storage.repository import Database

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def db(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'test.db'}")
    with database.scope(demo_tenant("demo-a")) as repo:
        import_jsonl(
            repo,
            (ROOT / "fixtures/demo/events.jsonl").read_bytes(),
            "demo",
            fixture_tenant="demo-a",
        )
    with database.scope(demo_tenant("demo-b")) as repo:
        import_jsonl(
            repo,
            (ROOT / "fixtures/demo/events.jsonl").read_bytes(),
            "demo",
            fixture_tenant="demo-b",
        )
    yield database
    database.engine.dispose()
