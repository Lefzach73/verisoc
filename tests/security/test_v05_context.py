import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.evidence.registry import EvidenceRegistry
from verisoc.ingest.importer import import_jsonl
from verisoc.investigation.evidence_pipeline import CaseWindow, open_window
from verisoc.storage.repository import Database
from verisoc.v05.context_derive import propose_context
from verisoc.v05.context_models import (
    ContextAuthority,
    ContextBundle,
    ContextCandidate,
    VerifiedContext,
    context_identity,
)
from verisoc.v05.context_verify import verify_context
from verisoc.v05.triage import triage

START = datetime(2027, 4, 1, tzinfo=UTC)


@contextmanager
def scenario(kind="auth", mutation=None):
    rows = [
        dict(
            event_code=4625,
            timestamp=(START + timedelta(seconds=i * 10)).isoformat(),
            host="workstation",
            user="account",
        )
        for i in range(6)
    ]
    rows.append(
        dict(
            event_code=4624,
            timestamp=(START + timedelta(seconds=80)).isoformat(),
            host="workstation",
            user="account",
        )
    )
    if kind == "process":
        rows = [
            dict(
                event_code=4688,
                timestamp=START.isoformat(),
                host="workstation",
                user="account",
                process="LAB-INDICATOR.EXE",
            )
        ]
    db = Database("sqlite:///:memory:")
    try:
        with db.scope(demo_tenant("demo-a")) as repo:
            raw = ("\n".join(json.dumps(r) for r in rows) + "\n").encode()
            import_jsonl(repo, raw, "dev-v05")
            events = repo.list_events("dev-v05")
            case = open_window(
                repo,
                CaseWindow(
                    dataset_id="dev-v05",
                    start_at=events[0].occurred_at,
                    end_at=events[-1].occurred_at,
                ),
            )
            record = dict(
                kind="approved_password_reset" if kind == "auth" else "approved_lab_execution",
                status="approved",
                ticket_id="new-synthetic-ticket",
                dataset_id="dev-v05",
                event_source_sha256=digest(raw),
                host_id=events[0].host_id,
                principal_id=events[0].user_id,
                approved_at=(START - timedelta(minutes=10)).isoformat(),
                valid_from=START.isoformat(),
                valid_until=(START + timedelta(minutes=5)).isoformat(),
                bindings=[
                    dict(event_id=str(e.event_id), canonical_sha256=e.canonical_sha256)
                    for e in events
                ],
            )
            if mutation:
                mutation(record)
            content = (json.dumps(record) + "\n").encode()
            authority = ContextAuthority(
                tenant_id=repo.tenant,
                dataset_id="dev-v05",
                source_id="test-custodian",
                file_sha256=digest(content),
                authorization_reference="synthetic-test-only",
            )
            yield repo, case, ContextBundle(authority=authority, content=content)
    finally:
        db.engine.dispose()


@pytest.mark.parametrize("kind", ["auth", "process"])
def test_context_explains_activity_without_removing_verified_facts_or_confirming_intent(kind):
    with scenario(kind) as (repo, case, bundle):
        without = triage(repo, case)
        with_context = triage(repo, case, (bundle,))
        assert without.triage_flag and not with_context.triage_flag
        assert with_context.disposition == "explained_activity"
        assert with_context.indicator_evidence == without.indicator_evidence
        assert with_context.verified_observations == without.verified_observations
        assert with_context.verified_context
        assert with_context.incident_verdict == "needs_review"


@pytest.mark.parametrize(
    "mutation",
    [
        "host",
        "principal",
        "dataset",
        "source_hash",
        "event_hash",
        "expired",
        "late_approval",
        "partial",
        "revoked",
    ],
)
def test_wrong_context_never_explains_a_real_indicator(mutation):
    def change(r):
        if mutation in ("host", "principal"):
            r[mutation + "_id"] = "wrong-identity"
        elif mutation == "dataset":
            r["dataset_id"] = "other-dataset"
        elif mutation == "source_hash":
            r["event_source_sha256"] = "0" * 64
        elif mutation == "event_hash":
            r["bindings"][0]["canonical_sha256"] = "0" * 64
        elif mutation == "expired":
            r["valid_until"] = START.isoformat()
        elif mutation == "late_approval":
            r["approved_at"] = (START + timedelta(seconds=1)).isoformat()
        elif mutation == "partial":
            r["bindings"] = r["bindings"][:1]
        else:
            r["status"] = "revoked"

    with scenario(mutation=change) as (repo, case, bundle):
        report = triage(repo, case, (bundle,))
        assert report.triage_flag and report.incident_verdict == "needs_review"
        assert not report.verified_context


def test_context_file_tampering_and_foreign_authority_fail_closed():
    with scenario() as (repo, case, bundle):
        altered = bundle.model_copy(update={"content": bundle.content + b" "})
        assert triage(repo, case, (altered,)).triage_flag
        foreign = bundle.model_copy(
            update={
                "authority": bundle.authority.model_copy(
                    update={"tenant_id": demo_tenant("demo-b")}
                )
            }
        )
        assert triage(repo, case, (foreign,)).triage_flag
        assert not triage(repo, case, (foreign,)).verified_context


def test_independent_verifier_rejects_resigned_producer_lies():
    with scenario() as (repo, case, bundle):
        fact = next(
            f
            for f in EvidenceRegistry(repo, case).facts.values()
            if f.predicate == "success_after_failures"
        )
        candidate = propose_context(repo, case, fact, bundle)[0]
        assert verify_context(repo, case, fact, candidate, bundle)
        data = candidate.model_dump(mode="json")
        data["activity"]["principal_id"] = "forged"
        altered = ContextCandidate.model_validate(data)
        altered = altered.model_copy(update={"fact_id": context_identity(altered)})
        assert verify_context(repo, case, fact, altered, bundle) is None
        with pytest.raises(ValidationError):
            VerifiedContext.model_validate(candidate.model_dump(mode="json"))


def test_duplicate_context_does_not_inflate_and_revocation_overrides_approval():
    with scenario() as (repo, case, bundle):
        content = bundle.content * 2
        duplicate = ContextBundle(
            content=content,
            authority=bundle.authority.model_copy(update={"file_sha256": digest(content)}),
        )
        report = triage(repo, case, (duplicate,))
        assert len(report.verified_context) == 2  # one per auth indicator, not per duplicate row
        revoked = json.loads(bundle.content)
        revoked["status"] = "revoked"
        content = bundle.content + (json.dumps(revoked) + "\n").encode()
        updated = ContextBundle(
            content=content,
            authority=bundle.authority.model_copy(update={"file_sha256": digest(content)}),
        )
        assert triage(repo, case, (updated,)).triage_flag


def test_unexplained_other_behavior_survives_partial_approval():
    with scenario() as (repo, case, bundle):
        # The reset approval cannot explain an image-match fact even with matching identity.
        r = json.loads(bundle.content)
        r["kind"] = "approved_lab_execution"
        content = (json.dumps(r) + "\n").encode()
        wrong = ContextBundle(
            content=content,
            authority=bundle.authority.model_copy(update={"file_sha256": digest(content)}),
        )
        assert triage(repo, case, (wrong,)).triage_flag


def test_conflicting_authority_snapshots_cannot_silently_use_stale_approval():
    with scenario() as (repo, case, bundle):
        with pytest.raises(ValueError, match="one pinned snapshot"):
            triage(repo, case, (bundle, bundle))


def test_runtime_context_and_triage_modules_cannot_import_evaluation_labels():
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "src/verisoc/v05"
    for path in root.glob("*.py"):
        if path.name == "cli.py":
            continue  # explicit offline research CLI boundary
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("verisoc.evaluation"), path
            if isinstance(node, ast.Import):
                assert all(not a.name.startswith("verisoc.evaluation") for a in node.names), path
