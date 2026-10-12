import json
from pathlib import Path

import httpx
import pytest
import yaml

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.detection.sigma_subset import compile_rule, detect_sigma
from verisoc.ingest.importer import import_jsonl
from verisoc.ingest.license_audit import audit_manifest, fetch
from verisoc.storage.repository import Database

ROOT = Path(__file__).resolve().parents[2]


def manifest(tmp_path, data, **changes):
    obj = dict(
        schema_version="1.0",
        dataset_id="audited-synthetic-test",
        source_url="https://example.invalid/events.jsonl",
        source_commit="1" * 40,
        sha256=digest(data),
        license_spdx="MIT",
        license_url="https://example.invalid/LICENSE",
        attribution="Original synthetic test",
        audit_status="approved",
        reviewer="automated-test-fixture",
        reviewed_on="2026-10-11",
        discrepancy=False,
    )
    obj.update(changes)
    path = tmp_path / "manifest.yml"
    path.write_text(yaml.safe_dump(obj))
    return path


def test_license_gates_download_and_checksum(tmp_path):
    data = (json.dumps(dict(event_code=4625, timestamp="2026-01-01T00:00:00Z")) + "\n").encode()
    path = manifest(tmp_path, data)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=data))
    with pytest.raises(ValueError, match="accept-license"):
        fetch(path, tmp_path / "raw.jsonl", transport=transport)
    output = fetch(path, tmp_path / "raw.jsonl", accept_license=True, transport=transport)
    assert output.read_bytes() == data
    with Database("sqlite:///:memory:").scope(demo_tenant("demo-a")) as repo:
        assert import_jsonl(repo, output.read_bytes(), "external-synthetic").accepted == 1
    with pytest.raises(FileExistsError):
        fetch(path, output, accept_license=True, transport=transport)
    bad = manifest(tmp_path, data, sha256="0" * 64)
    with pytest.raises(ValueError, match="checksum"):
        fetch(bad, tmp_path / "wrong.jsonl", accept_license=True, transport=transport)
    assert not (tmp_path / "wrong.jsonl").exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"audit_status": "pending"},
        {"reviewer": ""},
        {"discrepancy": True},
        {"source_url": "http://example.invalid/logs"},
    ],
)
def test_unapproved_and_conflicting_licenses_fail_closed(tmp_path, changes):
    with pytest.raises(ValueError):
        audit_manifest(manifest(tmp_path, b"synthetic", **changes))


def test_example_manifest_is_intentionally_blocked():
    with pytest.raises(ValueError, match="not been approved"):
        audit_manifest(ROOT / "datasets/external/example_manifest.yaml")


def test_pysigma_exact_subset_and_reject_unsupported(db):
    pytest.importorskip("sigma.collection", reason="optional extra sigma; run make test-sigma")
    content = (ROOT / "config/rules/lab-process.sigma.yml").read_text()
    rule_id, value = compile_rule(content)
    assert value == "lab-indicator.exe"
    with db.scope(demo_tenant("demo-a")) as repo:
        assert len(detect_sigma(repo, "demo", content)) == 1
    for bad in (
        content.replace("condition: selection", "condition: selection or other"),
        content.replace("process_name:", "process_name|contains:"),
        content.replace("lab-indicator.exe", '"*indicator*"'),
    ):
        with pytest.raises(ValueError, match="Unsupported"):
            compile_rule(bad)


def test_sigma_rejects_external_features_and_yaml_aliases():
    content = (ROOT / "config/rules/lab-process.sigma.yml").read_text()
    for bad in (
        content + "pipeline: arbitrary\n",
        content.replace("selection:", "selection: &selection"),
        content.replace("condition: selection", "condition: *selection"),
    ):
        with pytest.raises(ValueError):
            compile_rule(bad)
