import os
from datetime import timedelta

import pytest

from verisoc.core.errors import NotFound
from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.storage.repository import Database
from verisoc.v05.context_models import ActivityRecord, ContextAuthority, ContextBundle, EventBinding
from verisoc.v05.triage import triage

pytestmark = pytest.mark.postgres


def test_v05_context_uses_actual_restricted_postgres_scope():
    db = Database(os.environ["VERISOC_TEST_DATABASE_URL"], demo=False)
    try:
        with db.scope(demo_tenant("demo-a")) as repo:
            case = next(
                c
                for c in repo.list_cases()
                if c.alert and c.alert.rule_id == "auth_success_after_failures"
            )
            events = [repo.get_event(eid) for eid in case.event_ids]
            event = events[0]
            record = ActivityRecord(
                kind="approved_password_reset",
                status="approved",
                ticket_id="rls-test",
                dataset_id=case.dataset_id,
                event_source_sha256=event.source_ref.file_sha256,
                host_id=event.host_id,
                principal_id=event.user_id,
                approved_at=case.start_at - timedelta(minutes=1),
                valid_from=case.start_at,
                valid_until=case.end_at,
                bindings=tuple(
                    EventBinding(event_id=e.event_id, canonical_sha256=e.canonical_sha256)
                    for e in events
                ),
            )
            content = (record.model_dump_json() + "\n").encode()
            bundle = ContextBundle(
                content=content,
                authority=ContextAuthority(
                    tenant_id=repo.tenant,
                    dataset_id=case.dataset_id,
                    source_id="test-only",
                    file_sha256=digest(content),
                    authorization_reference="synthetic-test",
                ),
            )
            report = triage(repo, case, (bundle,))
            assert report.verified_context and not report.triage_flag
        with db.scope(demo_tenant("demo-b")) as repo:
            with pytest.raises(NotFound):
                triage(repo, case, (bundle,))
            own = repo.list_cases()[0]
            report = triage(repo, own, (bundle,))
            assert not report.verified_context
            assert str(case.case_id) not in report.model_dump_json()
    finally:
        db.engine.dispose()
