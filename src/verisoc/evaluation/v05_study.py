"""Immutable local study inputs. No provider endpoint or paid execution exists here."""

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

from verisoc.core.models import Frozen, Text
from verisoc.core.provenance import digest, json_hash
from verisoc.evaluation.v05_intake import (
    ContaminationIndex,
    IntakeManifest,
    read_pinned,
    validate_intake,
)


class StudyPlan(Frozen):
    schema_version: Literal["study-plan-1.0", "study-plan-1.1"] = "study-plan-1.1"
    study_id: Text
    model_id: Text
    model_revision: Text
    prompt_version: Literal["matched-offline-1.0"] = "matched-offline-1.0"
    arms: tuple[Literal["B0", "B2", "B3", "B3-hybrid-v0.5", "deterministic-verified"], ...] = (
        "B0",
        "B2",
        "B3",
        "B3-hybrid-v0.5",
        "deterministic-verified",
    )
    provider: Literal["mock"] = "mock"
    context_condition: Literal["events_only", "with_context"] = "events_only"
    max_tool_calls: Literal[8] = 8
    max_case_events: Literal[500] = 500
    max_selected_facts: Literal[32] = 32
    total_usd_cap: Literal[0] = 0
    seed: Literal[404] = 404
    bootstrap_replicates: Literal[10000] = 10000
    maximum_fpr_upper: Annotated[float, Field(ge=0.05, le=0.05)] = 0.05
    minimum_triage_coverage: Annotated[float, Field(ge=0.2, le=0.2)] = 0.2
    H1_rate_ratio: Annotated[float, Field(ge=0.5, le=0.5)] = 0.5
    H2_margin: Annotated[float, Field(ge=-0.05, le=-0.05)] = -0.05
    claims: Literal["smoke_only"] = "smoke_only"


def write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def source_identity(code_root: Path) -> dict[str, Any]:
    """A source archive is valid; an unrelated enclosing checkout is not its provenance."""
    metadata: dict[str, Any] = dict(git_sha=None, git_dirty=None, source_origin="source_archive")
    if not (code_root / ".git").exists():
        return metadata
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=code_root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode or Path(result.stdout.strip()).resolve() != code_root.resolve():
        raise ValueError("Source checkout identity cannot be established")
    revision = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=code_root,
        text=True,
        capture_output=True,
        check=False,
    )
    if revision.returncode:
        return dict(metadata, source_origin="uncommitted_repository", git_dirty=True)
    return dict(
        git_sha=revision.stdout.strip(),
        git_dirty=bool(
            subprocess.check_output(["git", "status", "--porcelain"], cwd=code_root, text=True)
        ),
        source_origin="git_checkout",
    )


def freeze_study(
    data_root: Path,
    intake: IntakeManifest,
    index: ContaminationIndex,
    plan: StudyPlan,
    code_root: Path,
    out: Path,
) -> dict[str, Any]:
    required = {"B0", "B2", "B3", "B3-hybrid-v0.5", "deterministic-verified"}
    if (
        set(plan.arms) != required
        or len(plan.arms) != len(required)
        or plan.study_id != intake.study_id
    ):
        raise ValueError("All paired arms and matching study identity are required")
    validation = validate_intake(data_root, intake, index)
    sources = {f.path: read_pinned(data_root, f) for f in intake.files}
    source_files = sorted(
        p for p in (code_root / "src/verisoc").rglob("*") if p.suffix in (".py", ".html")
    )
    if not source_files:
        raise ValueError("Actual implementation source required")
    snapshot = {str(p.relative_to(code_root)): digest(p.read_bytes()) for p in source_files}
    snapshot["uv.lock"] = digest((code_root / "uv.lock").read_bytes())
    snapshot["pyproject.toml"] = digest((code_root / "pyproject.toml").read_bytes())
    identity = source_identity(code_root)
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    write_new(out / "intake.json", json_bytes(intake.model_dump(mode="json")))
    write_new(out / "contamination.json", json_bytes(index.model_dump(mode="json")))
    write_new(out / "plan.json", json_bytes(plan.model_dump(mode="json")))
    write_new(out / "validation.json", json_bytes(validation))
    for name, content in sources.items():
        write_new(out / "inputs" / name, content)
    for name in snapshot:
        write_new(out / "source" / name, (code_root / name).read_bytes())
    manifest = dict(
        schema_version="study-freeze-1.1",
        created_at=datetime.now(UTC).isoformat(),
        **identity,
        source_code_sha256=snapshot,
        file_sha256={
            str(p.relative_to(out)): digest(p.read_bytes())
            for p in sorted(out.rglob("*"))
            if p.is_file()
        },
        validity="smoke_only",
        scientific_gate="BLOCKED",
        label_state="not supplied; no human reviews or signoffs fabricated",
        evidence_opportunity="same complete event window and bounded retrieval cap",
        context_policy="one frozen context condition, identical authorized packet for every arm",
    )
    write_new(out / "manifest.json", json_bytes(manifest))
    for path in out.rglob("*"):
        if path.is_file():
            path.chmod(0o444)
    return manifest


def verify_study(folder: Path, code_root: Path | None = None) -> dict[str, Any]:
    manifest: dict[str, Any] = json.loads((folder / "manifest.json").read_text())
    for name, expected in manifest["file_sha256"].items():
        candidate = folder / name
        if not candidate.resolve().is_relative_to(folder.resolve()) or candidate.is_symlink():
            raise ValueError("Unsafe frozen path")
        if digest(candidate.read_bytes()) != expected:
            raise ValueError("Frozen input changed")
    if manifest.get("schema_version") == "study-freeze-1.1":
        actual_files = {
            str(p.relative_to(folder))
            for p in folder.rglob("*")
            if p.is_file() and p != folder / "manifest.json"
        }
        if actual_files != set(manifest["file_sha256"]):
            raise ValueError("Frozen file inventory changed")
        required = {"intake.json", "contamination.json", "plan.json", "validation.json"}
        if not required <= actual_files or not manifest["source_code_sha256"]:
            raise ValueError("Incomplete study freeze")
        for name, expected in manifest["source_code_sha256"].items():
            path = folder / "source" / name
            if not path.resolve().is_relative_to((folder / "source").resolve()):
                raise ValueError("Unsafe source snapshot path")
            if digest(path.read_bytes()) != expected:
                raise ValueError("Archived implementation changed")
    if code_root:
        if manifest.get("schema_version") == "study-freeze-1.1":
            actual_source = {
                str(p.relative_to(code_root))
                for p in (code_root / "src/verisoc").rglob("*")
                if p.is_file() and p.suffix in (".py", ".html")
            }
            actual_source.update({"uv.lock", "pyproject.toml"})
            if actual_source != set(manifest["source_code_sha256"]):
                raise ValueError("Implementation inventory changed")
        for name, expected in manifest["source_code_sha256"].items():
            path = code_root / name
            if (
                not path.resolve().is_relative_to(code_root.resolve())
                or digest(path.read_bytes()) != expected
            ):
                raise ValueError("Frozen implementation changed")
    intake = IntakeManifest.model_validate_json((folder / "intake.json").read_text())
    index = ContaminationIndex.model_validate_json((folder / "contamination.json").read_text())
    plan = StudyPlan.model_validate_json((folder / "plan.json").read_text())
    if plan.study_id != intake.study_id:
        raise ValueError("Study identity mismatch")
    result = validate_intake(folder / "inputs", intake, index)
    if manifest.get("schema_version") == "study-freeze-1.1":
        if json_bytes(result) != (folder / "validation.json").read_bytes():
            raise ValueError("Frozen validation does not match source inputs")
    return manifest


def freeze_identity(folder: Path) -> str:
    return json_hash(json.loads((folder / "manifest.json").read_text()))
