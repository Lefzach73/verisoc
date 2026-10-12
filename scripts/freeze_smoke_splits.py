"""Explicit fixture split freeze; run only when documented fixture revisions are accepted."""

import json
from pathlib import Path

from verisoc.core.provenance import digest
from verisoc.evaluation.labels import load_labels
from verisoc.evaluation.splits import attach_fingerprints, split_families

root = Path(__file__).resolve().parents[1]
fixture = (root / "fixtures/demo/events.jsonl").read_bytes()
labels_path = root / "fixtures/demo/cases.jsonl"
labels = attach_fingerprints(load_labels(labels_path), fixture)
seed = 20261011
manifest = dict(
    schema_version="1.0",
    seed=seed,
    fixture_sha256=digest(fixture),
    labels_sha256=digest(labels_path.read_bytes()),
    splits=split_families(labels, seed),
    grouping="All auth-burst variants and low-count variants grouped before tuning",
)
(root / "config/splits-smoke.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n"
)
