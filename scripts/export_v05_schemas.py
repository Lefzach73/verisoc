"""Additive schema export; never rewrites the frozen v0.4 contracts."""

import argparse
import json
from pathlib import Path

from verisoc.api.auth import Auth
from verisoc.evaluation.v05_intake import IntakeManifest
from verisoc.evaluation.v05_review import SubmittedAdjudication, SubmittedReview
from verisoc.evaluation.v05_study import StudyPlan
from verisoc.storage.repository import Database
from verisoc.v05.api import create_app
from verisoc.v05.context_models import (
    ActivityRecord,
    ContextAuthority,
    ContextCandidate,
    VerifiedContext,
)
from verisoc.v05.triage import TriageReport

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, default=root / "docs/contracts/v05")
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
for model in (
    ActivityRecord,
    ContextAuthority,
    ContextCandidate,
    VerifiedContext,
    TriageReport,
    IntakeManifest,
    SubmittedReview,
    SubmittedAdjudication,
    StudyPlan,
):
    (args.out / f"{model.__name__}.json").write_text(
        json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
    )
db = Database("sqlite:///:memory:")
try:
    schema = create_app(db, Auth("synthetic-v05-schema-export-key-32-bytes")).openapi()
    (args.out / "openapi.json").write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
finally:
    db.engine.dispose()
