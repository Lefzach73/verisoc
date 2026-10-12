import json
from pathlib import Path

from typer.testing import CliRunner

from verisoc.cli import app

ROOT = Path(__file__).resolve().parents[2]


def test_documented_cli_flags_work(tmp_path):
    runner = CliRunner()
    db = str(tmp_path / "cli.db")
    assert runner.invoke(app, ["init", "--mode", "single-tenant-demo", "--db", db]).exit_code == 0
    result = runner.invoke(
        app,
        [
            "datasets",
            "import",
            "--input",
            str(ROOT / "fixtures/demo/events.jsonl"),
            "--tenant",
            "demo-a",
            "--db",
            db,
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["accepted"] == 236
    detected = runner.invoke(app, ["cases", "detect", "--dataset", "demo", "--db", db])
    assert detected.exit_code == 0
    case_id = json.loads(detected.output.splitlines()[0])["case_id"]
    investigated = runner.invoke(
        app, ["cases", "investigate", "--case-id", case_id, "--provider", "mock", "--db", db]
    )
    assert investigated.exit_code == 0 and "needs_review" in investigated.output
    shown = runner.invoke(app, ["reports", "show", "--case-id", case_id, "--db", db])
    assert shown.exit_code == 0 and "Verified observations" in shown.output
    blocked = runner.invoke(
        app,
        [
            "datasets",
            "audit-license",
            "--manifest",
            str(ROOT / "datasets/external/example_manifest.yaml"),
        ],
    )
    assert blocked.exit_code == 2 and "not been approved" in blocked.output


def test_v04_cli_window_facts_and_report(tmp_path):
    runner = CliRunner()
    db = str(tmp_path / "v04.db")
    result = runner.invoke(
        app,
        ["datasets", "import", "--input", str(ROOT / "fixtures/v04-dev/events.jsonl"), "--db", db],
    )
    assert result.exit_code == 0, result.output
    label = json.loads((ROOT / "fixtures/v04-dev/cases.jsonl").read_text().splitlines()[6])
    opened = runner.invoke(
        app,
        [
            "cases",
            "open-window",
            "--start",
            label["start_at"],
            "--end",
            label["end_at"],
            "--db",
            db,
        ],
    )
    assert opened.exit_code == 0, opened.output
    cid = json.loads(opened.output)["case_id"]
    facts = runner.invoke(app, ["cases", "facts", "--case-id", cid, "--db", db])
    assert facts.exit_code == 0 and json.loads(facts.output)["facts"]
    report = runner.invoke(app, ["cases", "investigate-v04", "--case-id", cid, "--db", db])
    assert report.exit_code == 0, report.output
    assert json.loads(report.output)["risk_assessment"] == "suspicious"
    assert json.loads(report.output)["incident_verdict"] == "needs_review"
