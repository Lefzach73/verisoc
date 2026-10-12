from pathlib import Path

from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect
from verisoc.ingest.importer import import_jsonl
from verisoc.llm.mock import propose
from verisoc.reporting.assemble import assemble
from verisoc.reporting.render import render
from verisoc.storage.repository import Database

root = Path(__file__).resolve().parents[1]
(root / "artifacts/demo").mkdir(parents=True, exist_ok=True)
db = Database(f"sqlite:///{root / 'artifacts/demo/verisoc.db'}")
with db.scope(demo_tenant("demo-a")) as repo:
    manifest = import_jsonl(
        repo, (root / "fixtures/demo/events.jsonl").read_bytes(), "demo", fixture_tenant="demo-a"
    )
    print(manifest.model_dump_json(indent=2, exclude={"event_ids"}))
    cases = detect(repo, "demo")
    assert cases, "Detector produced no actual alerts"
    case = next(c for c in cases if c.alert and c.alert.rule_id == "auth_burst")
    evidence = [repo.get_event(e) for e in case.event_ids]
    print(evidence[0].model_dump_json(indent=2))
    report = assemble(repo, case, propose(case, evidence))
    assert report.verified_claims and report.missing_evidence and report.verdict == "needs_review"
    print(f"Actual deterministic alerts: {len(cases)}")
    print(render(report))
