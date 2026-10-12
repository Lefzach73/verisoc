"""Synthetic tests of custody plumbing. No fixtures here constitute human evidence."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.evaluation.v05_context_inputs import StudyOracle
from verisoc.evaluation.v05_intake import ContaminationIndex, IntakeManifest, validate_intake
from verisoc.evaluation.v05_review import (
    SubmittedReview,
    adjudication_template,
    export_blind_forms,
    review_pair_hash,
    validate_submissions,
)
from verisoc.evaluation.v05_runner import MODEL_ID, run_frozen_mock
from verisoc.evaluation.v05_scoring import score_reviewed_run
from verisoc.evaluation.v05_study import StudyPlan, freeze_study, verify_study

ROOT = Path(__file__).resolve().parents[2]
EMPTY = ContaminationIndex(
    case_ids=(), origin_ids=(), family_ids=(), signatures=(), source_hashes=()
)


def context_intake(root):
    start = datetime(2027, 5, 1, tzinfo=UTC)
    rows = [
        dict(
            timestamp=(start + timedelta(days=case, seconds=i * 10)).isoformat(),
            event_code=4625 if i < 6 else 4624,
            host="unit-host",
            user="unit-user",
        )
        for case in range(2)
        for i in range(7)
    ]
    content = ("\n".join(json.dumps(r) for r in rows) + "\n").encode()
    tenant = demo_tenant("demo-a")
    oracle = StudyOracle(content, tenant, "completion-test")
    proofs = list(oracle.proofs.values())[:7]
    record = dict(
        kind="approved_password_reset",
        status="approved",
        ticket_id="synthetic-test",
        dataset_id="completion-test",
        event_source_sha256=digest(content),
        host_id=oracle.identity("unit-host", tenant),
        principal_id=oracle.identity("unit-user", tenant),
        approved_at=(start - timedelta(minutes=1)).isoformat(),
        valid_from=start.isoformat(),
        valid_until=(start + timedelta(minutes=5)).isoformat(),
        bindings=[
            dict(event_id=str(p.event_id), canonical_sha256=p.canonical_sha256) for p in proofs
        ],
    )
    context = (json.dumps(record) + "\n").encode()
    sources = {
        "events.jsonl": (content, "events"),
        "context.jsonl": (context, "context"),
        "permission.txt": (
            b"Synthetic unit test only; not a human permission or approval.",
            "permission",
        ),
    }
    for name, (body, _) in sources.items():
        (root / name).write_bytes(body)
    return IntakeManifest.model_validate(
        dict(
            study_id="completion-test",
            provenance="synthetic_development",
            custodian_id="unit-test",
            license_id="MIT",
            privacy_attestation="synthetic unit tests",
            permission_file="permission.txt",
            files=[
                dict(path=name, role=role, sha256=digest(body))
                for name, (body, role) in sources.items()
            ],
            cases=[
                dict(
                    case_id=f"case-{i}",
                    family_id="test-auth-family",
                    origin_incident_id=f"origin-{i}",
                    author_id="test-author",
                    tenant_id=str(tenant),
                    dataset_id="completion-test",
                    event_file="events.jsonl",
                    row_indexes=list(range(i * 7 + 1, i * 7 + 8)),
                    partition="development",
                    context_pins=["approval-pin"],
                )
                for i in range(2)
            ],
            context_sources=[
                dict(
                    pin_id="approval-pin",
                    file="context.jsonl",
                    authority=dict(
                        tenant_id=str(tenant),
                        dataset_id="completion-test",
                        source_id="unit-test-context",
                        file_sha256=digest(context),
                        authorization_reference="synthetic-only",
                    ),
                )
            ],
        )
    )


def freeze(root, manifest, condition="with_context"):
    out = root / "study"
    freeze_study(
        root,
        manifest,
        EMPTY,
        StudyPlan(
            study_id=manifest.study_id,
            model_id=MODEL_ID,
            model_revision="1.0",
            context_condition=condition,
        ),
        ROOT,
        out,
    )
    return out


def submissions(forms, labels=("benign", "benign")):
    mapping = json.loads((forms / "custodian-mapping.json").read_text())
    packets = json.loads((forms / "blind-packets.json").read_text())
    return tuple(
        SubmittedReview(
            blinded_case_id=p["blinded_case_id"],
            reviewer_id=reviewer,
            packet_sha256=mapping["packet_sha256"],
            label=labels[i % len(labels)],
            rationale="Synthetic unit-test structure, not an actual human judgment.",
            cited_event_ids=(p["evidence"][0]["event_id"],),
            blind_to_outputs=True,
            independent_of_authors=True,
            human_attestation_reference="synthetic-unit-test",
            submitted_at=datetime.now(UTC),
        )
        for p in packets
        for i, reviewer in enumerate(mapping["reviewer_ids"])
    )


@pytest.mark.parametrize("condition", ["with_context", "events_only"])
def test_context_reaches_frozen_comparators_and_reviewers_without_cross_case_leakage(
    tmp_path, condition
):
    study = freeze(tmp_path, context_intake(tmp_path), condition)
    assert run_frozen_mock(study, ROOT, tmp_path / "run")["failed_rows"] == 0
    rows = json.loads((tmp_path / "run/rows.json").read_text())
    packets = json.loads((tmp_path / "run/packets.json").read_text())
    first = {r["arm"]: r for r in rows if r["case_id"] == "case-0"}
    second = {r["arm"]: r for r in rows if r["case_id"] == "case-1"}
    for arm in ("B3-hybrid-v0.5", "deterministic-verified"):
        assert first[arm]["triage_flag"] == (condition == "events_only")
        assert second[arm]["triage_flag"] is True
        assert first[arm]["unsupported_facts"] == second[arm]["unsupported_facts"] == 0
    assert len({r["evidence_opportunity_sha256"] for r in first.values()}) == 1
    assert bool(packets[0]["packet"]["recorded_context"]) == (condition == "with_context")
    assert packets[1]["packet"]["recorded_context"] == []
    forms = tmp_path / "forms"
    export_blind_forms(study, ("reviewer-a", "reviewer-b"), forms)
    blind = json.loads((forms / "blind-packets.json").read_text())
    # Reviewers establish ground truth with all authorized context, even in events-only ablations.
    assert len(blind[0]["recorded_context"]) == 1
    assert blind[1]["recorded_context"] == []
    reviews = submissions(forms)
    context_id = blind[0]["recorded_context"][0]["context_id"]
    reviews = (reviews[0].model_copy(update={"cited_event_ids": (context_id,)}), *reviews[1:])
    assert validate_submissions(forms, reviews)["structural_status"] == "PASS"


@pytest.mark.parametrize(
    "mutation", ["tenant", "dataset", "hash", "unknown_pin", "foreign_event", "unpinned"]
)
def test_context_intake_rejects_scope_and_pin_corruption(tmp_path, mutation):
    data = context_intake(tmp_path).model_dump(mode="json")
    authority = data["context_sources"][0]["authority"]
    if mutation == "tenant":
        authority["tenant_id"] = str(demo_tenant("demo-b"))
    elif mutation == "dataset":
        authority["dataset_id"] = "different"
    elif mutation == "hash":
        authority["file_sha256"] = "0" * 64
    elif mutation == "unknown_pin":
        data["cases"][0]["context_pins"] = ["unknown"]
    elif mutation == "unpinned":
        data["context_sources"] = []
    else:
        record = json.loads((tmp_path / "context.jsonl").read_text())
        record["bindings"][0]["event_id"] = str(demo_tenant("demo-b"))
        body = (json.dumps(record) + "\n").encode()
        (tmp_path / "context.jsonl").write_bytes(body)
        authority["file_sha256"] = data["files"][1]["sha256"] = digest(body)
    with pytest.raises(ValueError):
        validate_intake(tmp_path, IntakeManifest.model_validate(data), EMPTY)


def test_hybrid_selection_omissions_are_real_and_deterministic_reference_is_preserved(
    tmp_path, monkeypatch
):
    import verisoc.evaluation.v05_runner as runner
    from verisoc.investigation.evidence_pipeline import FactSelection

    original = runner.common_proposal

    def omit(*args):
        proposal, _ = original(*args)
        return proposal, FactSelection(fact_ids=())

    study = freeze(tmp_path, context_intake(tmp_path), "events_only")
    monkeypatch.setattr(runner, "common_proposal", omit)
    run_frozen_mock(study, ROOT, tmp_path / "run")
    rows = json.loads((tmp_path / "run/rows.json").read_text())
    for row in rows:
        if row["arm"] == "B3-hybrid-v0.5":
            assert not row["triage_flag"] and row["omitted_indicators"] == 2
            assert "indicator_not_selected" in row["reasons"]
            assert (
                row["emitted_fact_count"] == 9
            )  # all seven observations and two indicators remain
        elif row["arm"] == "deterministic-verified":
            assert row["triage_flag"]


def test_freeze_archives_source_and_detects_unlisted_files(tmp_path):
    study = freeze(tmp_path, context_intake(tmp_path))
    manifest = verify_study(study, ROOT)
    for name, expected in manifest["source_code_sha256"].items():
        assert digest((study / "source" / name).read_bytes()) == expected
    (study / "source/unlisted.py").write_text("# unexpected")
    with pytest.raises(ValueError, match="inventory"):
        verify_study(study)


@pytest.mark.parametrize(
    "mutation", ["pair_hash", "packet_hash", "citation", "time", "self_review"]
)
def test_adjudication_requires_original_judgments_and_available_evidence(tmp_path, mutation):
    study = freeze(tmp_path, context_intake(tmp_path))
    forms = tmp_path / "forms"
    export_blind_forms(study, ("reviewer-a", "reviewer-b"), forms)
    reviews = submissions(forms, ("benign", "malicious"))
    result = validate_submissions(forms, reviews)
    adjudication_template(forms, result, tmp_path / "third.html")
    html = (tmp_path / "third.html").read_text()
    assert "review_pair_sha256" in html and "textContent" in html and "PAYLOAD" not in html
    decisions = {}
    for cid in result["unresolved_disagreements"]:
        pair = [r.model_dump(mode="json") for r in reviews if r.blinded_case_id == cid]
        decisions[cid] = dict(
            adjudicator_id="reviewer-c",
            label="needs_review",
            packet_sha256=pair[0]["packet_sha256"],
            review_pair_sha256=review_pair_hash(pair),
            cited_event_ids=pair[0]["cited_event_ids"],
            rationale="Synthetic adjudication for test only.",
            human_attestation_reference="test-only",
            submitted_at=datetime.now(UTC).isoformat(),
        )
    assert validate_submissions(forms, reviews, decisions)["structural_status"] == "PASS"
    decision = next(iter(decisions.values()))
    field, value = dict(
        pair_hash=("review_pair_sha256", "0" * 64),
        packet_hash=("packet_sha256", "0" * 64),
        citation=("cited_event_ids", ["absent"]),
        time=("submitted_at", "2020-01-01T00:00:00Z"),
        self_review=("adjudicator_id", "reviewer-a"),
    )[mutation]
    decision[field] = value
    with pytest.raises(ValueError):
        validate_submissions(forms, reviews, decisions)


def test_no_holdout_cannot_pass_numerical_gates_and_tampered_mapping_is_rejected(tmp_path):
    study = freeze(tmp_path, context_intake(tmp_path))
    forms = tmp_path / "forms"
    export_blind_forms(study, ("a", "b"), forms)
    reviews = submissions(forms)
    run_frozen_mock(study, ROOT, tmp_path / "run")
    result = score_reviewed_run(study, tmp_path / "run", forms, reviews, None, tmp_path / "score")
    assert result["partitions"]["development"]["cases"] == 2
    assert result["primary"]["cases"] == 0 and result["primary_partition"] == "holdout"
    assert result["numerical_screens"]["simultaneous_status"] == "BLOCKED"
    assert all(s["status"] == "BLOCKED" for s in result["numerical_screens"]["checks"].values())
    run_manifest = tmp_path / "run/manifest.json"
    original = run_manifest.read_text()
    altered = json.loads(original)
    del altered["output_sha256"]["rows.json"]
    run_manifest.write_text(json.dumps(altered))
    with pytest.raises(ValueError, match="Incomplete run"):
        score_reviewed_run(study, tmp_path / "run", forms, reviews, None, tmp_path / "unbound")
    run_manifest.write_text(original)
    (forms / "custodian-mapping.json").write_text("{}")
    with pytest.raises(ValueError, match="Review artifact changed"):
        validate_submissions(forms, reviews)


def test_scoring_keeps_partitions_separate_and_checks_frozen_family_ids(tmp_path):
    data = context_intake(tmp_path).model_dump(mode="json")
    # Simulate the externally supplied intake path inside pytest only. No real independence claim.
    data["provenance"] = "external_independent_candidate"
    data["context_sources"] = []
    data["files"] = [f for f in data["files"] if f["role"] != "context"]
    raw = [
        dict(
            timestamp=f"2027-01-0{i + 1}T00:00:00Z",
            event_code=code,
            host="test-host",
            user="test-user",
        )
        for i, code in enumerate((4624, 4688, 3))
    ]
    content = ("\n".join(json.dumps(r) for r in raw) + "\n").encode()
    (tmp_path / "events.jsonl").write_bytes(content)
    data["files"][0]["sha256"] = digest(content)
    template = data["cases"][0]
    data["cases"] = [
        dict(
            template,
            case_id=f"case-{i}",
            family_id=f"family-{i}",
            origin_incident_id=f"origin-{i}",
            row_indexes=[i + 1],
            partition=part,
            context_pins=[],
        )
        for i, part in enumerate(("development", "calibration", "holdout"))
    ]
    study = freeze(tmp_path, IntakeManifest.model_validate(data), "events_only")
    forms, run = tmp_path / "forms", tmp_path / "run"
    export_blind_forms(study, ("a", "b"), forms)
    reviews = submissions(forms)
    run_frozen_mock(study, ROOT, run)
    result = score_reviewed_run(study, run, forms, reviews, None, tmp_path / "score")
    for partition in result["partitions"].values():
        assert partition["cases"] == 1
        assert partition["arms"]["B2"]["benign_fpr_counts"]["denominator"] == 1
    assert result["arms"]["B2"]["benign_fpr_counts"]["denominator"] == 3
    assert result["primary"]["arms"]["B2"]["benign_fpr_counts"]["denominator"] == 1
    assert result["scientific_status"] == "BLOCKED"
    rows = json.loads((run / "rows.json").read_text())
    rows[0]["family_id"] = "rewritten-family"
    (run / "rows.json").write_text(json.dumps(rows))
    manifest = json.loads((run / "manifest.json").read_text())
    manifest["output_sha256"]["rows.json"] = digest((run / "rows.json").read_bytes())
    (run / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="frozen family"):
        score_reviewed_run(study, run, forms, reviews, None, tmp_path / "invalid-score")
