import json
from pathlib import Path

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.evaluation.v05_oracle import ContextOracle
from verisoc.evidence.registry import EvidenceRegistry
from verisoc.ingest.importer import import_jsonl
from verisoc.investigation.evidence_pipeline import CaseWindow, open_window
from verisoc.storage.repository import Database
from verisoc.v05.context_models import (
    ContextAuthority,
    ContextBundle,
    ContextCandidate,
    context_identity,
)
from verisoc.v05.triage import triage

ROOT = Path(__file__).resolve().parents[2]


def test_context_oracle_checks_original_source_and_rejects_resigned_counterfacts():
    content = (ROOT / "fixtures/v05-dev/events.jsonl").read_bytes()
    context = (ROOT / "fixtures/v05-dev/context-demo-a.jsonl").read_bytes()
    label = json.loads((ROOT / "fixtures/v05-dev/cases.jsonl").read_text().splitlines()[0])
    oracle = ContextOracle(content, "v05-dev")
    db = Database("sqlite:///:memory:")
    try:
        with db.scope(demo_tenant("demo-a")) as repo:
            import_jsonl(repo, content, "v05-dev", fixture_tenant="demo-a")
            case = open_window(
                repo,
                CaseWindow.model_validate(
                    dict(dataset_id="v05-dev", start_at=label["start_at"], end_at=label["end_at"])
                ),
            )
            bundle = ContextBundle(
                content=context,
                authority=ContextAuthority(
                    tenant_id=repo.tenant,
                    dataset_id="v05-dev",
                    source_id="test-only",
                    file_sha256=digest(context),
                    authorization_reference="test",
                ),
            )
            registry = EvidenceRegistry(repo, case)
            report = triage(repo, case, (bundle,))
            for claim in report.verified_context:
                fact = registry.facts[claim.explained_fact_id]
                assert oracle.supports_context(case, fact, claim, bundle)
                for field in ("raw_row_sha256", "file_sha256"):
                    data = claim.model_dump(mode="json", exclude={"verification_status"})
                    data["source_proof"][field] = "0" * 64
                    fake = ContextCandidate.model_validate(data)
                    fake = fake.model_copy(update={"fact_id": context_identity(fake)})
                    assert not oracle.supports_context(case, fact, fake, bundle)
    finally:
        db.engine.dispose()
