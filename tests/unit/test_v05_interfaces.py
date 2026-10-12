import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from verisoc.api.auth import Auth
from verisoc.cli import app as legacy_cli
from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect
from verisoc.v05.api import create_app
from verisoc.v05.cli import app

ROOT = Path(__file__).resolve().parents[2]


def test_v05_cli_uses_real_import_and_preserves_endpoint_separation(tmp_path):
    runner = CliRunner()
    db = str(tmp_path / "offline.db")
    imported = runner.invoke(
        legacy_cli,
        [
            "datasets",
            "import",
            "--input",
            str(ROOT / "fixtures/v05-dev/events.jsonl"),
            "--dataset",
            "v05-dev",
            "--db",
            db,
        ],
    )
    assert imported.exit_code == 0, imported.output
    label = json.loads((ROOT / "fixtures/v05-dev/cases.jsonl").read_text().splitlines()[0])
    opened = runner.invoke(
        legacy_cli,
        [
            "cases",
            "open-window",
            "--dataset",
            "v05-dev",
            "--db",
            db,
            "--start",
            label["start_at"],
            "--end",
            label["end_at"],
        ],
    )
    assert opened.exit_code == 0, opened.output
    case_id = json.loads(opened.output)["case_id"]
    result = runner.invoke(app, ["triage", "--case-id", case_id, "--db", db])
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["triage_flag"] and report["incident_verdict"] == "needs_review"


def test_v05_api_authentication_and_tenant_boundary(db):
    secret = "synthetic-v05-interface-key-32-characters"
    client = TestClient(create_app(db, Auth(secret)))
    now = datetime.now(UTC)

    def headers(name):
        token = jwt.encode(
            dict(
                sub="test",
                tenant_id=str(demo_tenant(name)),
                iat=now,
                nbf=now,
                exp=now + timedelta(minutes=5),
                iss="verisoc-research",
                aud="verisoc-api",
            ),
            secret,
            algorithm="HS256",
        )
        return {"Authorization": "Bearer " + token}

    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
    url = f"/v05/cases/{case.case_id}/triage"
    assert client.post(url).status_code == 401
    assert client.post(url, headers=headers("demo-b")).status_code == 404
    result = client.post(url, headers=headers("demo-a"))
    assert result.status_code == 200
    assert result.json()["incident_verdict"] == "needs_review"


def test_v05_api_rejects_user_supplied_authority(db):
    secret = "synthetic-v05-context-api-key-32-characters"
    client = TestClient(create_app(db, Auth(secret)))
    now = datetime.now(UTC)
    token = jwt.encode(
        dict(
            sub="test",
            tenant_id=str(demo_tenant("demo-a")),
            iat=now,
            nbf=now,
            exp=now + timedelta(minutes=5),
            iss="verisoc-research",
            aud="verisoc-api",
        ),
        secret,
        algorithm="HS256",
    )
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
    result = client.post(
        f"/v05/cases/{case.case_id}/triage",
        headers={"Authorization": "Bearer " + token},
        json={"authority": {"approved": True}, "tenant_id": str(demo_tenant("demo-b"))},
    )
    assert result.status_code == 422
