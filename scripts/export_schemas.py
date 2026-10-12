import json
from pathlib import Path

from verisoc.api.auth import Auth
from verisoc.api.main import create_app
from verisoc.core.models import (
    Alert,
    CandidateClaim,
    CandidateReport,
    CanonicalEvent,
    Case,
    ImportManifest,
    InvestigationReport,
    RawEvent,
    VerifiedClaim,
)
from verisoc.evidence.models import FactCandidate, VerifiedFact
from verisoc.investigation.evidence_pipeline import (
    CaseWindow,
    EvidencePacket,
    EvidenceReport,
    FactSelection,
)
from verisoc.investigation.tool_router import TOOL_SCHEMAS
from verisoc.storage.repository import Database

root = Path(__file__).resolve().parents[1]
folder = root / "docs/contracts"
folder.mkdir(parents=True, exist_ok=True)
for model in (
    FactCandidate,
    VerifiedFact,
    CaseWindow,
    EvidencePacket,
    FactSelection,
    EvidenceReport,
    RawEvent,
    CanonicalEvent,
    Alert,
    Case,
    CandidateClaim,
    CandidateReport,
    VerifiedClaim,
    InvestigationReport,
    ImportManifest,
    *TOOL_SCHEMAS.values(),
):
    (folder / (model.__name__ + ".json")).write_text(
        json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
    )
db = Database("sqlite:///:memory:")
try:
    schema = create_app(db, Auth("synthetic-schema-export-key-32-bytes")).openapi()
    (root / "docs/openapi.json").write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
finally:
    db.engine.dispose()
