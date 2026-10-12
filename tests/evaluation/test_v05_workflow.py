"""All identities/judgments here are synthetic pytest-only fixtures, never human results."""

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.evaluation.v05_review import review_pair_hash
from verisoc.evaluation.v05_workflow import (
    resume_workflow,
    start_workflow,
    workflow_status,
)

ROOT = Path(__file__).resolve().parents[2]
REVIEWERS = ("pytest-reviewer-a", "pytest-reviewer-b")


def prepared(tmp_path):
    source = tmp_path / "inputs"
    source.mkdir()
    content = b'{"timestamp":"2027-01-01T00:00:00Z","event_code":4624,"host":"pytest-host"}\n'
    permission = b"Synthetic pytest fixture: not an external permission or approval."
    (source / "events.jsonl").write_bytes(content)
    (source / "permission.txt").write_bytes(permission)
    manifest = dict(
        study_id="workflow-test",
        provenance="synthetic_development",
        custodian_id="pytest-custodian",
        license_id="MIT",
        privacy_attestation="synthetic-only",
        permission_file="permission.txt",
        files=[
            dict(path="events.jsonl", sha256=digest(content), role="events"),
            dict(path="permission.txt", sha256=digest(permission), role="permission"),
        ],
        cases=[
            dict(
                case_id="pytest-case",
                family_id="pytest-family",
                origin_incident_id="pytest-origin",
                author_id="pytest-author",
                tenant_id=str(demo_tenant("demo-a")),
                dataset_id="pytest-data",
                event_file="events.jsonl",
                row_indexes=[1],
                partition="development",
            )
        ],
    )
    (source / "intake.json").write_text(json.dumps(manifest))
    (source / "contamination.json").write_text(
        json.dumps(dict(case_ids=[], origin_ids=[], family_ids=[], signatures=[], source_hashes=[]))
    )
    (source / "plan.json").write_text(
        json.dumps(
            dict(
                study_id="workflow-test",
                model_id="matched-engineering-smoke-1",
                model_revision="1.0",
            )
        )
    )
    workflow = tmp_path / "prepared"
    result = start_workflow(
        source / "intake.json",
        source / "contamination.json",
        source / "plan.json",
        REVIEWERS,
        ROOT,
        workflow,
    )
    assert result["status"] == "AWAITING_HUMAN_REVIEWS"
    return source, workflow


def submissions(tmp_path, workflow, disagree=False):
    mapping = json.loads((workflow / "reviews/custodian-mapping.json").read_text())
    packet = json.loads((workflow / "reviews/blind-packets.json").read_text())[0]
    paths = []
    records = []
    for i, reviewer in enumerate(REVIEWERS):
        review = dict(
            blinded_case_id=packet["blinded_case_id"],
            reviewer_id=reviewer,
            packet_sha256=mapping["packet_sha256"],
            label="malicious" if disagree and i else "benign",
            rationale="Pytest-only synthetic judgment, not an actual human submission.",
            cited_event_ids=[packet["evidence"][0]["event_id"]],
            blind_to_outputs=True,
            independent_of_authors=True,
            human_attestation_reference="pytest-only; unverified",
            submitted_at=datetime.now(UTC).isoformat(),
        )
        path = tmp_path / f"review-{i}.json"
        path.write_text(json.dumps([review]))
        paths.append(path)
        records.append(review)
    return tuple(paths), records


def test_preparation_reuses_pipeline_and_refuses_overwrite(tmp_path):
    source, workflow = prepared(tmp_path)
    state = workflow_status(workflow)
    assert state["scientific_status"] == "BLOCKED"
    assert state["human_authenticity_verified"] is False
    assert state["arm_rows"] == 5 and state["failed_rows"] == 0
    assert len(state["stages"]) == 5 and all(s["status"] == "PASS" for s in state["stages"])
    assert (workflow / "study/source/src/verisoc/evaluation/v05_workflow.py").exists()
    assert not (workflow / "score").exists()
    before = (workflow / "workflow-manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        start_workflow(
            source / "intake.json",
            source / "contamination.json",
            source / "plan.json",
            REVIEWERS,
            ROOT,
            workflow,
        )
    assert (workflow / "workflow-manifest.json").read_bytes() == before
    # Original source changes do not mutate the frozen workflow inputs.
    (source / "events.jsonl").write_text("changed outside the freeze")
    assert workflow_status(workflow) == state


def test_supplied_reviews_score_descriptively_and_bind_input_bytes(tmp_path):
    _, workflow = prepared(tmp_path)
    paths, _ = submissions(tmp_path, workflow)
    out = tmp_path / "scored"
    result = resume_workflow(workflow, paths, None, ROOT, out)
    assert result["status"] == "SCORED_DESCRIPTIVE_ONLY"
    assert result["scientific_status"] == "BLOCKED"
    assert result["human_authenticity_verified"] is False
    assert workflow_status(out) == result
    assert (out / "request/reviews-1.json").read_bytes() == paths[0].read_bytes()
    score = json.loads((out / "score/score.json").read_text())
    assert score["primary"]["cases"] == 0
    assert score["arms"]["B0"]["benign_fpr_counts"]["denominator"] == 1
    with pytest.raises(FileExistsError):
        resume_workflow(workflow, paths, None, ROOT, out)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "empty", "wrong_packet", "wrong_citation", "one_reviewer", "duplicate_key"],
)
def test_missing_or_tampered_reviews_cannot_score(tmp_path, mutation):
    _, workflow = prepared(tmp_path)
    paths, records = submissions(tmp_path, workflow)
    if mutation == "missing":
        paths[1].unlink()
    elif mutation == "empty":
        paths[1].write_text("[]")
    elif mutation == "one_reviewer":
        paths = paths[:1]
    elif mutation == "duplicate_key":
        paths[1].write_text('[{"label":"benign","label":"malicious"}]')
    else:
        field, value = (
            ("packet_sha256", "0" * 64)
            if mutation == "wrong_packet"
            else ("cited_event_ids", ["unavailable"])
        )
        records[1][field] = value
        paths[1].write_text(json.dumps([records[1]]))
    out = tmp_path / "rejected"
    result = resume_workflow(workflow, paths, None, ROOT, out)
    assert result["status"] == "FAILED"
    assert result["scientific_status"] == "BLOCKED"
    assert result["stages"][-1]["status"] == "FAILED"
    assert not (out / "score").exists()
    assert workflow_status(out) == result


def test_disagreement_needs_bound_third_reviewer_export_before_scoring(tmp_path):
    _, workflow = prepared(tmp_path)
    paths, records = submissions(tmp_path, workflow, disagree=True)
    result = resume_workflow(workflow, paths, None, ROOT, tmp_path / "conflicts")
    assert result["status"] == "AWAITING_ADJUDICATION"
    assert (tmp_path / "conflicts/adjudication.html").exists()
    assert not (tmp_path / "conflicts/score").exists()
    decision = dict(
        adjudicator_id="pytest-third-reviewer",
        label="needs_review",
        packet_sha256=records[0]["packet_sha256"],
        review_pair_sha256=review_pair_hash(
            json.loads((tmp_path / "conflicts/review-validation.json").read_text())[
                "original_reviews"
            ]
        ),
        rationale="Synthetic pytest adjudication; no independent human is represented.",
        cited_event_ids=records[0]["cited_event_ids"],
        human_attestation_reference="pytest-only",
        submitted_at=datetime.now(UTC).isoformat(),
    )
    adjudication = tmp_path / "adjudication.json"
    adjudication.write_text(json.dumps({records[0]["blinded_case_id"]: decision}))
    scored = resume_workflow(workflow, paths, adjudication, ROOT, tmp_path / "adjudicated")
    assert scored["status"] == "SCORED_DESCRIPTIVE_ONLY"
    assert scored["human_authenticity_verified"] is False
    decision["review_pair_sha256"] = "0" * 64
    adjudication.write_text(json.dumps({records[0]["blinded_case_id"]: decision}))
    rejected = resume_workflow(workflow, paths, adjudication, ROOT, tmp_path / "bad-adjudication")
    assert rejected["status"] == "FAILED"
    assert not (tmp_path / "bad-adjudication/score").exists()


@pytest.mark.parametrize("mutation", ["run", "source", "extra_file"])
def test_prepared_artifact_changes_fail_closed(tmp_path, mutation):
    _, workflow = prepared(tmp_path)
    path = (
        workflow
        / {
            "run": "run/rows.json",
            "source": "study/source/pyproject.toml",
            "extra_file": "unexpected.txt",
        }[mutation]
    )
    if path.exists():
        path.chmod(0o600)
    path.write_text("changed")
    with pytest.raises(ValueError, match="inventory or content changed"):
        workflow_status(workflow)
    paths, _ = submissions(tmp_path, workflow)
    result = resume_workflow(workflow, paths, None, ROOT, tmp_path / "refused")
    assert result["status"] == "FAILED"
    assert result["stages"][-1]["stage"] == "verify_preparation"


def test_failed_intake_is_archived_without_exception_text(tmp_path):
    source, _ = prepared(tmp_path)
    data = json.loads((source / "intake.json").read_text())
    data["files"][0]["sha256"] = "0" * 64
    (source / "intake.json").write_text(json.dumps(data))
    out = tmp_path / "failed-intake"
    result = start_workflow(
        source / "intake.json",
        source / "contamination.json",
        source / "plan.json",
        REVIEWERS,
        ROOT,
        out,
    )
    assert result["status"] == "FAILED"
    assert result["stages"][-1]["stage"] == "intake"
    assert result["stages"][-1]["error_code"] == "ValueError"
    assert (out / "request/intake.json").exists()
    assert not (out / "study").exists()
    assert workflow_status(out) == result


def test_resume_cannot_write_inside_or_over_prepared_directory(tmp_path):
    _, workflow = prepared(tmp_path)
    paths, _ = submissions(tmp_path, workflow)
    with pytest.raises(ValueError, match="must not alter"):
        resume_workflow(workflow, paths, None, ROOT, workflow / "score")
    with pytest.raises(ValueError, match="replace or contain"):
        resume_workflow(workflow, paths, None, ROOT, tmp_path)


def test_manual_script_status_exit_codes(tmp_path):
    _, workflow = prepared(tmp_path)
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            "scripts/research_workflow.py",
            "status",
            "--workflow",
            str(workflow),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "AWAITING_HUMAN_REVIEWS"
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            "scripts/research_workflow.py",
            "status",
            "--workflow",
            str(tmp_path / "absent"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "FAILED"


@pytest.mark.parametrize(
    "reviewers", [("same", "same"), (" ", "reviewer-b"), ("pytest-author", "reviewer-b")]
)
def test_reviewer_assignment_cannot_be_empty_duplicate_or_case_author(tmp_path, reviewers):
    source, _ = prepared(tmp_path)
    out = tmp_path / "invalid-assignment"
    result = start_workflow(
        source / "intake.json",
        source / "contamination.json",
        source / "plan.json",
        reviewers,
        ROOT,
        out,
    )
    assert result["status"] == "FAILED"
    assert not (out / "run").exists()
    assert workflow_status(out) == result


def test_changed_live_implementation_cannot_score_frozen_study(tmp_path):
    _, workflow = prepared(tmp_path)
    paths, _ = submissions(tmp_path, workflow)
    other_code = tmp_path / "different-source"
    other_code.mkdir()
    result = resume_workflow(workflow, paths, None, other_code, tmp_path / "mismatched-source")
    assert result["status"] == "FAILED"
    assert result["stages"][-1]["stage"] == "verify_preparation"


def test_provider_failures_remain_in_paired_denominators(tmp_path, monkeypatch):
    import verisoc.evaluation.v05_runner as runner

    def failure(*args):
        raise TimeoutError("private-provider-content-must-not-appear")

    source, _ = prepared(tmp_path)
    monkeypatch.setattr(runner, "common_proposal", failure)
    out = tmp_path / "provider-failure"
    result = start_workflow(
        source / "intake.json",
        source / "contamination.json",
        source / "plan.json",
        REVIEWERS,
        ROOT,
        out,
    )
    assert result["status"] == "PREPARED_WITH_FAILURES"
    assert result["arm_rows"] == 5 and result["failed_rows"] == 3
    assert "private-provider-content" not in (out / "status.json").read_text()
    paths, _ = submissions(tmp_path, out)
    scored = resume_workflow(out, paths, None, ROOT, tmp_path / "failure-score")
    assert scored["status"] == "SCORED_DESCRIPTIVE_ONLY"
    assert scored["scientific_status"] == "BLOCKED"
