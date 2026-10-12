"""Explicit audited download and validation of supported defensive JSONL only."""

import argparse
from pathlib import Path

from verisoc.core.ids import stable_id
from verisoc.ingest.importer import import_jsonl
from verisoc.ingest.license_audit import audit_manifest, fetch
from verisoc.storage.repository import Database

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--manifest", type=Path, required=True)
parser.add_argument(
    "--out", type=Path, required=True, help="External/ignored path for audited source"
)
parser.add_argument("--accept-license", action="store_true")
args = parser.parse_args()
manifest = audit_manifest(args.manifest)
path = fetch(args.manifest, args.out, accept_license=args.accept_license)
db = Database("sqlite:///:memory:")
try:
    with db.scope(stable_id("external-audit-local")) as repo:
        imported = import_jsonl(repo, path.read_bytes(), manifest.dataset_id)
        print(imported.model_dump_json(indent=2, exclude={"event_ids"}))
finally:
    db.engine.dispose()
