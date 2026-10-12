"""New author-defined context controls. Historical data are never enriched or overwritten."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.ingest.importer import import_jsonl
from verisoc.storage.repository import Database

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = (
    "approved_reset",
    "approved_lab",
    "routine_login",
    "routine_process",
    "unapproved_sequence",
    "unapproved_lab",
    "wrong_scope",
    "expired_approval",
    "uncertain_sequence",
    "revoked_approval",
    "incomplete_binding",
    "mixed_activity",
)


def main():
    folder = ROOT / "fixtures/v05-dev"
    if folder.exists():
        raise SystemExit("Refusing to overwrite v0.5 development fixtures")
    events = []
    labels = []
    for index, name in enumerate(TEMPLATES):
        for variant, tenant in enumerate(("demo-a", "demo-b")):
            start = datetime(2027, 5, 1, tzinfo=UTC) + timedelta(hours=index * 2 + variant)

            def event(code, seconds, _start=start, _tenant=tenant, **extra):
                return dict(
                    fixture_tenant=_tenant,
                    event_code=code,
                    timestamp=(_start + timedelta(seconds=seconds)).isoformat(),
                    host="context-lab-host",
                    user="context-lab-user",
                    **extra,
                )

            rows = [event(4625, i * 10) for i in range(6)] + [event(4624, 80)]
            if name in ("approved_lab", "unapproved_lab", "routine_process"):
                rows = [
                    event(
                        4688,
                        0,
                        process="lab-indicator.exe" if name != "routine_process" else "normal.exe",
                    )
                ]
            if name == "routine_login":
                rows = [event(4624, 0)]
            if name == "mixed_activity":
                rows.append(event(4688, 90, process="lab-indicator.exe"))
            if variant:
                rows.reverse()
            gold = (
                "benign"
                if name in ("approved_reset", "approved_lab", "routine_login", "routine_process")
                else "needs_review"
                if name in ("uncertain_sequence", "incomplete_binding")
                else "malicious"
            )
            labels.append(
                dict(
                    scenario_id=f"v05-control-{index:02}-{variant}",
                    template=name,
                    tenant=tenant,
                    family="process"
                    if name in ("approved_lab", "unapproved_lab", "routine_process")
                    else "auth",
                    verdict=gold,
                    start_at=min(r["timestamp"] for r in rows),
                    end_at=max(r["timestamp"] for r in rows),
                    partition="development",
                    annotation="author_defined_software_controls_not_independent",
                )
            )
            events.extend(rows)
    content = ("\n".join(json.dumps(r, sort_keys=True) for r in events) + "\n").encode()
    contexts = {name: [] for name in ("demo-a", "demo-b")}
    db = Database("sqlite:///:memory:")
    try:
        for tenant in contexts:
            with db.scope(demo_tenant(tenant)) as repo:
                import_jsonl(repo, content, "v05-dev", fixture_tenant=tenant)
                admitted = repo.list_events("v05-dev")
                for label in (r for r in labels if r["tenant"] == tenant):
                    name = label["template"]
                    if name in (
                        "routine_login",
                        "routine_process",
                        "unapproved_sequence",
                        "unapproved_lab",
                        "uncertain_sequence",
                    ):
                        continue
                    local = [
                        e
                        for e in admitted
                        if label["start_at"] <= e.occurred_at.isoformat() <= label["end_at"]
                    ]
                    selected = [
                        e
                        for e in local
                        if name != "mixed_activity" or e.attributes.event_code != 4688
                    ]
                    start = local[0].occurred_at
                    record = dict(
                        kind="approved_lab_execution"
                        if name == "approved_lab"
                        else "approved_password_reset",
                        status="revoked" if name == "revoked_approval" else "approved",
                        ticket_id=f"synthetic-{label['scenario_id']}",
                        dataset_id="v05-dev",
                        event_source_sha256=digest(content),
                        host_id=local[0].host_id,
                        principal_id=local[0].user_id,
                        approved_at=(start - timedelta(minutes=10)).isoformat(),
                        valid_from=start.isoformat(),
                        valid_until=(start + timedelta(minutes=5)).isoformat(),
                        bindings=[
                            dict(event_id=str(e.event_id), canonical_sha256=e.canonical_sha256)
                            for e in selected
                        ],
                    )
                    if name == "wrong_scope":
                        record["host_id"] = "id-other-host"
                    if name == "expired_approval":
                        record["valid_until"] = start.isoformat()
                    if name == "incomplete_binding":
                        record["bindings"] = record["bindings"][:1]
                    contexts[tenant].append(record)
    finally:
        db.engine.dispose()
    folder.mkdir()
    (folder / "events.jsonl").write_bytes(content)
    (folder / "cases.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in labels)
    )
    for tenant, data in contexts.items():
        (folder / f"context-{tenant}.jsonl").write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in data)
        )
    print(
        json.dumps(
            dict(
                cases=len(labels),
                source_records=len(events),
                context_records=sum(map(len, contexts.values())),
                scope="new synthetic software controls, not independent incidents",
            )
        )
    )


if __name__ == "__main__":
    main()
