"""Explicit, bounded local research steps; never schedules work or supplies judgments."""

import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from verisoc.core.models import Text
from verisoc.core.provenance import digest
from verisoc.evaluation.v05_intake import ContaminationIndex, IntakeManifest, validate_intake
from verisoc.evaluation.v05_review import (
    SubmittedReview,
    adjudication_template,
    validate_submissions,
)
from verisoc.evaluation.v05_runner import run_frozen_mock
from verisoc.evaluation.v05_scoring import score_reviewed_run
from verisoc.evaluation.v05_study import (
    StudyPlan,
    freeze_study,
    json_bytes,
    verify_study,
    write_new,
)
from verisoc.v05.context_source import unique_fields

MAX_JSON = 8 * 1048576


def _read_json(path: Path) -> tuple[bytes, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("A regular JSON input file is required")
    with path.open("rb") as handle:
        content = handle.read(MAX_JSON + 1)
    if not content or len(content) > MAX_JSON:
        raise ValueError("JSON input size exceeded")
    return content, json.loads(content, object_pairs_hook=unique_fields)


def _inventory(folder: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    total_bytes = 0
    for number, path in enumerate(folder.rglob("*")):
        if number >= 8192:
            raise ValueError("Workflow directory-entry limit exceeded")
        if path.is_symlink():
            raise ValueError("Workflow artifacts cannot contain symlinks")
        if not path.is_file() or path == folder / "workflow-manifest.json":
            continue
        total_bytes += path.stat().st_size
        if len(files) >= 4096 or total_bytes > 512 * 1048576:
            raise ValueError("Workflow artifact limit exceeded")
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1048576), b""):
                hasher.update(chunk)
        files[str(path.relative_to(folder))] = hasher.hexdigest()
    return files


def _fresh(out: Path, protected: tuple[Path, ...]) -> Path:
    out = out.absolute()
    if out.is_symlink() or any(p.resolve().is_relative_to(out.resolve()) for p in protected):
        raise ValueError("Output cannot replace or contain an input")
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    return out


def _initial(kind: str) -> dict[str, Any]:
    return dict(
        schema_version="research-workflow-1.0",
        operation=kind,
        status="FAILED",
        scientific_status="BLOCKED",
        human_authenticity_verified=False,
        model_validity="mock_software_smoke_only",
        created_at=datetime.now(UTC).isoformat(),
        stages=[],
        external_blockers=[
            "Custodian verification of source permission, independence, blinding and identities.",
            "Independent human judgments and claim annotations; AI cannot supply these.",
            "Cluster-aware power analysis and external preregistration.",
            "A validated incident decision policy and separately authorized real-model study.",
        ],
        design_screen=dict(
            minimum_total_holdout_cases=200,
            minimum_distinct_holdout_families=20,
            minimum_adjudicated_benign_controls=100,
            interpretation="Existing numerical screen only, not proof of statistical power.",
            unresolved="Custodian must clarify the protocol's separate incident-count target.",
        ),
        next_commands=[],
    )


def _finish(out: Path, result: dict[str, Any]) -> dict[str, Any]:
    write_new(out / "status.json", json_bytes(result))
    write_new(
        out / "workflow-manifest.json",
        json_bytes(
            dict(
                schema_version="workflow-manifest-1.0",
                file_sha256=_inventory(out),
                trust="Local integrity record, not a digital signature or human approval.",
            )
        ),
    )
    for path in out.rglob("*"):
        if path.is_file():
            path.chmod(0o444)
    return result


def _stage(result: dict[str, Any], name: str, action: Any) -> Any:
    started = time.perf_counter()
    record: dict[str, Any] = dict(stage=name, status="FAILED", error_code=None, duration_ms=None)
    result["stages"].append(record)
    try:
        value = action()
        record["status"] = "PASS"
        return value
    except Exception as exc:
        # Input/provider exception text can contain private evidence. Preserve the stage,
        # class and partial artifacts without copying that text into a status report.
        record["error_code"] = type(exc).__name__
        raise
    finally:
        record["duration_ms"] = (time.perf_counter() - started) * 1000


def start_workflow(
    manifest: Path,
    contamination: Path,
    plan: Path,
    reviewer_ids: tuple[str, str],
    code_root: Path,
    out: Path,
) -> dict[str, Any]:
    """Run each offline preparation stage once, retaining any failure in a fresh folder."""
    if out.resolve().is_relative_to((code_root / "src").resolve()):
        raise ValueError("Workflow artifacts must remain outside implementation source")
    out = _fresh(out, (manifest, contamination, plan))
    result = _initial("prepare")
    try:

        def load_inputs() -> tuple[IntakeManifest, ContaminationIndex, StudyPlan]:
            values: list[Any] = []
            for name, path in (
                ("intake", manifest),
                ("contamination", contamination),
                ("plan", plan),
            ):
                content, value = _read_json(path)
                write_new(out / "request" / f"{name}.json", content)
                values.append(value)
            reviewers = TypeAdapter(tuple[Text, Text]).validate_python(reviewer_ids)
            if len(set(reviewers)) != 2 or any(not r.strip() for r in reviewers):
                raise ValueError("Two explicit, distinct reviewer assignments required")
            write_new(out / "request/reviewers.json", json_bytes(reviewers))
            return (
                IntakeManifest.model_validate(values[0]),
                ContaminationIndex.model_validate(values[1]),
                StudyPlan.model_validate(values[2]),
            )

        intake, index, study_plan = _stage(result, "load_inputs", load_inputs)
        validation = _stage(
            result, "intake", lambda: validate_intake(manifest.parent, intake, index)
        )
        write_new(out / "intake-validation.json", json_bytes(validation))
        _stage(
            result,
            "freeze",
            lambda: freeze_study(
                manifest.parent, intake, index, study_plan, code_root, out / "study"
            ),
        )
        from verisoc.evaluation.v05_review import export_blind_forms

        _stage(
            result,
            "blank_review_forms",
            lambda: export_blind_forms(out / "study", reviewer_ids, out / "reviews"),
        )
        summary = _stage(
            result, "matched_mock", lambda: run_frozen_mock(out / "study", code_root, out / "run")
        )
        result.update(
            status="PREPARED_WITH_FAILURES" if summary["failed_rows"] else "AWAITING_HUMAN_REVIEWS",
            cases=summary["cases"],
            arm_rows=summary["arm_rows"],
            failed_rows=summary["failed_rows"],
            source_snapshot_sha256=digest((out / "study/manifest.json").read_bytes()),
            human_review_status="BLOCKED: no submitted reviews supplied",
            next_commands=[
                ["python", "scripts/research_workflow.py", "status", "--workflow", str(out)],
                [
                    "python",
                    "scripts/research_workflow.py",
                    "resume",
                    "--workflow",
                    str(out),
                    "--submissions",
                    "<reviewer-1.json>",
                    "--submissions",
                    "<reviewer-2.json>",
                    "--out",
                    "<new-private-output-directory>",
                ],
            ],
            distribution=(
                "Give each reviewer only their own reviewer-N.html. Keep mapping/run private."
            ),
        )
    except Exception:
        result["next_steps"] = [
            "Inspect failed stage; correct inputs and start in a new directory."
        ]
    return _finish(out, result)


def workflow_status(folder: Path) -> dict[str, Any]:
    """Verify the exact local inventory before showing its recorded status; never mutates it."""
    _, manifest = _read_json(folder / "workflow-manifest.json")
    if manifest.get("schema_version") != "workflow-manifest-1.0":
        raise ValueError("Unsupported workflow manifest")
    if _inventory(folder) != manifest["file_sha256"]:
        raise ValueError("Workflow artifact inventory or content changed")
    _, status = _read_json(folder / "status.json")
    if status.get("schema_version") != "research-workflow-1.0":
        raise ValueError("Unsupported workflow status")
    if status["operation"] == "prepare" and status["status"] != "FAILED":
        verify_study(folder / "study")
    return dict(status)


def resume_workflow(
    workflow: Path,
    submissions: tuple[Path, ...],
    adjudications: Path | None,
    code_root: Path,
    out: Path,
) -> dict[str, Any]:
    """Validate supplied judgments, then score or export adjudication; no synthetic answers."""
    if out.resolve().is_relative_to(workflow.resolve()):
        raise ValueError("Resumed results must not alter the prepared workflow")
    out = _fresh(out, (workflow, *submissions, *((adjudications,) if adjudications else ())))
    result = _initial("review_and_score")
    try:

        def verify_preparation() -> None:
            state = workflow_status(workflow)
            if state["operation"] != "prepare" or state["status"] not in (
                "AWAITING_HUMAN_REVIEWS",
                "PREPARED_WITH_FAILURES",
            ):
                raise ValueError("An intact, completed preparation is required")
            verify_study(workflow / "study", code_root)
            result["prepared_workflow_sha256"] = digest(
                (workflow / "workflow-manifest.json").read_bytes()
            )
            write_new(
                out / "request/prepared-workflow-manifest.json",
                (workflow / "workflow-manifest.json").read_bytes(),
            )

        _stage(result, "verify_preparation", verify_preparation)

        def load_reviews() -> tuple[tuple[SubmittedReview, ...], dict[str, Any] | None]:
            if not 1 <= len(submissions) <= 2:
                raise ValueError("Supply one combined file or the two reviewer exports")
            values: list[Any] = []
            for i, path in enumerate(submissions, 1):
                content, data = _read_json(path)
                write_new(out / "request" / f"reviews-{i}.json", content)
                if not isinstance(data, list) or len(values) + len(data) > 1000:
                    raise ValueError("Review list limit exceeded")
                values.extend(data)
            decisions = None
            if adjudications:
                content, decisions = _read_json(adjudications)
                write_new(out / "request/adjudications.json", content)
                if not isinstance(decisions, dict) or len(decisions) > 500:
                    raise ValueError("Adjudication object limit exceeded")
            return TypeAdapter(tuple[SubmittedReview, ...]).validate_python(values), decisions

        reviews, decisions = _stage(result, "load_submissions", load_reviews)
        validated = _stage(
            result,
            "validate_submissions",
            lambda: validate_submissions(workflow / "reviews", reviews, decisions),
        )
        write_new(out / "review-validation.json", json_bytes(validated))
        if validated["unresolved_disagreements"]:
            _stage(
                result,
                "adjudication_form",
                lambda: adjudication_template(
                    workflow / "reviews", validated, out / "adjudication.html"
                ),
            )
            result.update(
                status="AWAITING_ADJUDICATION",
                human_review_status="BLOCKED: unresolved submitted disagreements",
                next_commands=[
                    [
                        "python",
                        "scripts/research_workflow.py",
                        "resume",
                        "--workflow",
                        str(workflow),
                        *[v for p in submissions for v in ("--submissions", str(p))],
                        "--adjudications",
                        "<independent-adjudicator-export.json>",
                        "--out",
                        "<another-new-private-output-directory>",
                    ]
                ],
            )
        else:
            _stage(
                result,
                "descriptive_scoring",
                lambda: score_reviewed_run(
                    workflow / "study",
                    workflow / "run",
                    workflow / "reviews",
                    reviews,
                    decisions,
                    out / "score",
                ),
            )
            result.update(
                status="SCORED_DESCRIPTIVE_ONLY",
                human_review_status="STRUCTURE_VALID; human authenticity remains unverified",
                next_steps=[
                    "Independent custodian must verify external scientific gates "
                    "before any efficacy claim."
                ],
            )
    except Exception:
        result["next_steps"] = [
            "Inspect failed stage; retain this attempt and retry in a fresh directory."
        ]
    return _finish(out, result)
