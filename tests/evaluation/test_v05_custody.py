import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.evaluation.v05_intake import (
    ContaminationIndex,
    IntakeManifest,
    relative_signature,
    validate_intake,
)
from verisoc.evaluation.v05_review import (
    SubmittedReview,
    export_blind_forms,
    review_pair_hash,
    validate_submissions,
)
from verisoc.evaluation.v05_study import StudyPlan, freeze_study, verify_study

ROOT = Path(__file__).resolve().parents[2]
EMPTY = ContaminationIndex(
    case_ids=(), origin_ids=(), family_ids=(), signatures=(), source_hashes=()
)


def intake(tmp_path):
    content = (
        b'{"timestamp":"2027-01-01T00:00:00Z","event_code":4624,'
        b'"host":"unit-host","user":"unit-user"}\n'
    )
    (tmp_path / "events.jsonl").write_bytes(content)
    permission = b"Synthetic unit-test permission placeholder, not a real approval."
    (tmp_path / "permission.txt").write_bytes(permission)
    return IntakeManifest.model_validate(
        dict(
            study_id="test-study",
            provenance="synthetic_development",
            custodian_id="test-custodian",
            license_id="MIT",
            privacy_attestation="synthetic-only",
            permission_file="permission.txt",
            files=[
                dict(path="events.jsonl", sha256=digest(content), role="events"),
                dict(path="permission.txt", sha256=digest(permission), role="permission"),
            ],
            cases=[
                dict(
                    case_id="internal-case",
                    family_id="unit-family",
                    origin_incident_id="unit-origin",
                    author_id="fixture-author",
                    tenant_id=str(demo_tenant("demo-a")),
                    dataset_id="study-events",
                    event_file="events.jsonl",
                    row_indexes=[1],
                    partition="development",
                )
            ],
        )
    )


def seal(tmp_path):
    manifest = intake(tmp_path)
    out = tmp_path / "freeze"
    freeze_study(
        tmp_path,
        manifest,
        EMPTY,
        StudyPlan(
            study_id=manifest.study_id, model_id="matched-engineering-smoke-1", model_revision="1.0"
        ),
        ROOT,
        out,
    )
    return out


def test_intake_and_freeze_are_immutable_and_do_not_create_human_signoffs(tmp_path):
    folder = seal(tmp_path)
    assert verify_study(folder)["scientific_gate"] == "BLOCKED"
    with pytest.raises(FileExistsError):
        freeze_study(
            tmp_path,
            intake(tmp_path),
            EMPTY,
            StudyPlan(
                study_id="test-study", model_id="matched-engineering-smoke-1", model_revision="1.0"
            ),
            ROOT,
            folder,
        )
    path = folder / "inputs/events.jsonl"
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="Frozen input changed"):
        verify_study(folder)


@pytest.mark.parametrize(
    "mutation",
    [
        "path_escape",
        "bad_hash",
        "duplicate_case",
        "row_zero",
        "row_string",
        "row_duplicate",
        "fake_holdout",
        "missing_permission",
        "renamed_sibling",
    ],
)
def test_intake_rejects_invalid_or_contaminated_inputs(tmp_path, mutation):
    original = intake(tmp_path)
    data = original.model_dump(mode="json")
    index = EMPTY
    if mutation == "path_escape":
        data["files"][0]["path"] = "../escape"
    elif mutation == "bad_hash":
        data["files"][0]["sha256"] = "0" * 64
    elif mutation == "duplicate_case":
        data["cases"] *= 2
    elif mutation == "row_zero":
        data["cases"][0]["row_indexes"] = [0]
    elif mutation == "row_string":
        data["cases"][0]["row_indexes"] = ["1"]
    elif mutation == "row_duplicate":
        data["cases"][0]["row_indexes"] = [1, 1]
    elif mutation == "missing_permission":
        data["permission_file"] = "absent"
    elif mutation == "fake_holdout":
        data["cases"][0]["partition"] = "holdout"
    else:
        checked = validate_intake(tmp_path, original, EMPTY)
        index = EMPTY.model_copy(
            update={"signatures": (checked["cases"][0]["relative_signature"],)}
        )
        data["provenance"] = "external_independent_candidate"
        data["cases"][0].update(
            case_id="renamed-case", family_id="renamed-family", partition="holdout"
        )
    with pytest.raises((ValueError, ValidationError)):
        validate_intake(tmp_path, IntakeManifest.model_validate(data), index)


def test_signature_is_invariant_to_time_and_entity_renaming():
    base = [
        dict(timestamp="2027-01-01T00:00:00Z", event_code=4625, host="a", user="x"),
        dict(timestamp="2027-01-01T00:00:05Z", event_code=4624, host="a", user="x"),
    ]
    shifted = []
    for row in base:
        r = dict(row)
        r["host"] = "different-host"
        r["user"] = "different-user"
        r["timestamp"] = (
            datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")) + timedelta(days=80)
        ).isoformat()
        shifted.append(r)
    assert relative_signature(base) == relative_signature(shifted)


def test_blind_forms_hide_metadata_and_require_two_real_submissions(tmp_path):
    folder = seal(tmp_path)
    forms = tmp_path / "forms"
    result = export_blind_forms(folder, ("reviewer-a", "reviewer-b"), forms)
    assert result["submitted_human_reviews"] == 0 and not result["human_authenticity_verified"]
    for path in forms.glob("reviewer-*.html"):
        content = path.read_text()
        assert "internal-case" not in content and "unit-family" not in content
        assert "PAYLOAD" not in content and "connect-src 'none'" in content
    with pytest.raises(ValueError, match="Two actual"):
        validate_submissions(forms, ())
    packet = json.loads((forms / "blind-packets.json").read_text())[0]

    def review(reviewer, label):
        return SubmittedReview(
            blinded_case_id=packet["blinded_case_id"],
            reviewer_id=reviewer,
            packet_sha256=result["packet_sha256"],
            label=label,
            rationale="Unit-test rationale, not a human judgment.",
            cited_event_ids=(packet["evidence"][0]["event_id"],),
            blind_to_outputs=True,
            independent_of_authors=True,
            human_attestation_reference="unit-test-only",
            submitted_at=datetime.now(UTC),
        )

    reviews = (review("reviewer-a", "malicious"), review("reviewer-b", "benign"))
    disagreement = validate_submissions(forms, reviews)
    assert disagreement["structural_status"] == "BLOCKED"
    cid = packet["blinded_case_id"]
    adjudication = {
        cid: dict(
            adjudicator_id="third-test-reviewer",
            label="needs_review",
            rationale="Synthetic adjudication fixture, not an actual human review.",
            human_attestation_reference="test",
            packet_sha256=result["packet_sha256"],
            review_pair_sha256=review_pair_hash([r.model_dump(mode="json") for r in reviews]),
            cited_event_ids=[packet["evidence"][0]["event_id"]],
            submitted_at=datetime.now(UTC).isoformat(),
        )
    }
    accepted = validate_submissions(forms, reviews, adjudication)
    assert accepted["structural_status"] == "PASS" and not accepted["human_authenticity_verified"]
    with pytest.raises(ValueError, match="Duplicate"):
        validate_submissions(forms, reviews + (reviews[0],))


def test_study_plan_does_not_allow_threshold_redefinition_or_paid_provider():
    with pytest.raises(ValidationError):
        StudyPlan(study_id="x", model_id="x", model_revision="1", maximum_fpr_upper=0.99)
    with pytest.raises(ValidationError):
        StudyPlan(study_id="x", model_id="x", model_revision="1", provider="hosted")


def test_matched_mock_preserves_all_cases_and_candidate_pairing(tmp_path):
    from verisoc.evaluation.v05_runner import run_frozen_mock

    folder = seal(tmp_path)
    result = run_frozen_mock(folder, ROOT, tmp_path / "run")
    assert result["cases"] == 1 and result["arm_rows"] == 5 and result["failed_rows"] == 0
    rows = json.loads((tmp_path / "run/rows.json").read_text())
    assert len({r["evidence_opportunity_sha256"] for r in rows}) == 1
    model = [r for r in rows if r["arm"] in ("B2", "B3", "B3-hybrid-v0.5")]
    assert len({r["shared_proposal_sha256"] for r in model}) == 1
    assert result["human_labels_available"] is False
    with pytest.raises(FileExistsError):
        run_frozen_mock(folder, ROOT, tmp_path / "run")


def test_failed_proposal_is_retained_without_erasing_deterministic_arms(tmp_path, monkeypatch):
    import verisoc.evaluation.v05_runner as runner

    folder = seal(tmp_path)

    def fail(*args):
        raise TimeoutError("do-not-leak-sensitive-provider-text")

    monkeypatch.setattr(runner, "common_proposal", fail)
    result = runner.run_frozen_mock(folder, ROOT, tmp_path / "failed-run")
    assert result["arm_rows"] == 5 and result["failed_rows"] == 3
    data = (tmp_path / "failed-run/rows.json").read_text()
    assert "do-not-leak" not in data
    rows = json.loads(data)
    assert all(r["error"] is None for r in rows if r["arm"] in ("B0", "deterministic-verified"))


def test_post_review_scoring_keeps_nulls_and_blocks_scientific_claims(tmp_path):
    from verisoc.evaluation.v05_runner import run_frozen_mock
    from verisoc.evaluation.v05_scoring import score_reviewed_run

    folder = seal(tmp_path)
    forms = tmp_path / "forms"
    run = tmp_path / "run"
    exported = export_blind_forms(folder, ("reviewer-a", "reviewer-b"), forms)
    run_frozen_mock(folder, ROOT, run)
    packet = json.loads((forms / "blind-packets.json").read_text())[0]
    reviews = tuple(
        SubmittedReview(
            blinded_case_id=packet["blinded_case_id"],
            reviewer_id=reviewer,
            packet_sha256=exported["packet_sha256"],
            label="benign",
            rationale="Synthetic scoring fixture; this is not an actual human judgment.",
            cited_event_ids=(packet["evidence"][0]["event_id"],),
            blind_to_outputs=True,
            independent_of_authors=True,
            human_attestation_reference="unit-test",
            submitted_at=datetime.now(UTC),
        )
        for reviewer in ("reviewer-a", "reviewer-b")
    )
    result = score_reviewed_run(folder, run, forms, reviews, None, tmp_path / "score")
    assert result["scientific_status"] == "BLOCKED"
    for arm in result["arms"].values():
        assert arm["recall_counts"]["denominator"] == 0
        assert arm["triage"]["recall"] is None
        assert arm["benign_fpr_counts"]["denominator"] == 1
    (run / "rows.json").write_text("[]")
    with pytest.raises(ValueError, match="Recorded run changed"):
        score_reviewed_run(folder, run, forms, reviews, None, tmp_path / "bad-score")


def test_frozen_review_form_uses_safe_text_for_source_injection(tmp_path):
    data = intake(tmp_path).model_dump(mode="json")
    records = json.loads((tmp_path / "events.jsonl").read_text())
    records["process"] = "</script><script>window.bad=true</script>"
    (tmp_path / "events.jsonl").write_text(json.dumps(records) + "\n")
    data["files"][0]["sha256"] = digest((tmp_path / "events.jsonl").read_bytes())
    manifest = IntakeManifest.model_validate(data)
    folder = tmp_path / "freeze"
    freeze_study(
        tmp_path,
        manifest,
        EMPTY,
        StudyPlan(
            study_id="test-study", model_id="matched-engineering-smoke-1", model_revision="1.0"
        ),
        ROOT,
        folder,
    )
    forms = tmp_path / "forms"
    export_blind_forms(folder, ("a", "b"), forms)
    text = (forms / "reviewer-1.html").read_text()
    assert "window.bad=true" not in text
    assert "pre.textContent" in text and "innerHTML" not in text


def test_one_dataset_identity_cannot_pin_two_different_files(tmp_path):
    manifest = intake(tmp_path).model_dump(mode="json")
    content = b'{"timestamp":"2027-01-02T00:00:00Z","event_code":4624}\n'
    (tmp_path / "different.jsonl").write_bytes(content)
    manifest["files"].append(dict(path="different.jsonl", role="events", sha256=digest(content)))
    second = dict(
        manifest["cases"][0],
        case_id="other-case",
        origin_incident_id="other-origin",
        event_file="different.jsonl",
    )
    manifest["cases"].append(second)
    with pytest.raises(ValueError, match="conflicting source"):
        validate_intake(tmp_path, IntakeManifest.model_validate(manifest), EMPTY)


def test_hybrid_id_gate_does_not_leak_into_the_unverified_B2_comparator(tmp_path, monkeypatch):
    from uuid import uuid4

    import verisoc.evaluation.v05_runner as runner
    from verisoc.investigation.evidence_pipeline import FactSelection

    original = runner.common_proposal

    def unknown_id(case, events, facts, context_records=None):
        candidate, _ = original(case, events, facts, context_records)
        return candidate, FactSelection(fact_ids=(uuid4(),))

    folder = seal(tmp_path)
    monkeypatch.setattr(runner, "common_proposal", unknown_id)
    result = runner.run_frozen_mock(folder, ROOT, tmp_path / "different-gates")
    assert result["failed_rows"] == 1
    rows = {r["arm"]: r for r in json.loads((tmp_path / "different-gates/rows.json").read_text())}
    assert rows["B2"]["error"] is None and rows["B3"]["error"] is None
    assert rows["B3-hybrid-v0.5"]["error"] == "unoffered_fact_id"
