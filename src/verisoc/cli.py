import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect
from verisoc.ingest.importer import MAX_BYTES, import_jsonl
from verisoc.investigation.pipeline import investigate
from verisoc.llm.base import Budget
from verisoc.llm.mock import MockProvider
from verisoc.reporting.render import render
from verisoc.storage.repository import DEMO_MODE, Database

app = typer.Typer(no_args_is_help=True)
datasets = typer.Typer()
cases = typer.Typer()
reports = typer.Typer()
app.add_typer(datasets, name="datasets")
app.add_typer(cases, name="cases")
app.add_typer(reports, name="reports")


def database(db: Path) -> Database:
    db.parent.mkdir(parents=True, exist_ok=True)
    return Database(f"sqlite:///{db}")


@app.command()
def init(mode: str = "single-tenant-demo", db: Path = Path("artifacts/demo/verisoc.db")) -> None:
    if mode != "single-tenant-demo":
        raise typer.BadParameter(
            "Use PostgreSQL migration and API configuration for authenticated mode"
        )
    database(db)
    typer.echo(DEMO_MODE)


@datasets.command("import")
def import_dataset(
    input: Annotated[Path, typer.Option(exists=True, readable=True)],
    tenant: str = "demo-a",
    dataset: str = "demo",
    db: Path = Path("artifacts/demo/verisoc.db"),
    fixture: bool = False,
) -> None:
    with input.open("rb") as handle:
        content = handle.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise typer.BadParameter("Import size exceeded")
    first = json.loads(content.splitlines()[0]) if content.splitlines() else {}
    synthetic = fixture or (isinstance(first, dict) and "fixture_tenant" in first)
    with database(db).scope(demo_tenant(tenant)) as repo:
        manifest = import_jsonl(
            repo, content, dataset, fixture_tenant=tenant if synthetic else None
        )
        typer.echo(manifest.model_dump_json(indent=2))


@cases.command("detect")
def detect_cases(
    sigma_rule: Path | None = None,
    dataset: str = "demo",
    tenant: str = "demo-a",
    db: Path = Path("artifacts/demo/verisoc.db"),
) -> None:
    with database(db).scope(demo_tenant(tenant)) as repo:
        result = detect(repo, dataset)
        if sigma_rule:
            from verisoc.detection.sigma_subset import detect_sigma

            result += detect_sigma(repo, dataset, sigma_rule.read_text())
        for case in result:
            typer.echo(case.model_dump_json())


@cases.command("investigate")
def investigate_case(
    case_id: Annotated[UUID, typer.Option()],
    provider: str = "mock",
    tenant: str = "demo-a",
    db: Path = Path("artifacts/demo/verisoc.db"),
) -> None:
    if provider != "mock":
        raise typer.BadParameter("Real adapters require explicit evaluation configuration")
    with database(db).scope(demo_tenant(tenant)) as repo:
        case = repo.get_case(case_id)
        typer.echo(render(investigate(repo, case, MockProvider(), Budget())))


@reports.command("show")
def show_report(
    case_id: Annotated[UUID, typer.Option()],
    tenant: str = "demo-a",
    db: Path = Path("artifacts/demo/verisoc.db"),
) -> None:
    with database(db).scope(demo_tenant(tenant)) as repo:
        typer.echo(render(repo.get_report(case_id)))


@app.command("evaluate")
def evaluate(
    config: Path = Path("config/eval-smoke.yaml"),
    provider: str = "mock",
    out: Path = Path("artifacts/runs"),
) -> None:
    from verisoc.evaluation.runner import run

    typer.echo(str(run(config, out, provider)))


@datasets.command("audit-license")
def audit_license(manifest: Annotated[Path, typer.Option(exists=True, readable=True)]) -> None:
    from verisoc.ingest.license_audit import audit_manifest

    try:
        result = audit_manifest(manifest)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc
    typer.echo(result.model_dump_json(indent=2))


def main() -> None:
    from verisoc.core.errors import VeriSOCError

    try:
        app()
    except VeriSOCError as exc:
        typer.echo(exc.code, err=True)
        raise SystemExit(2) from exc
    except (ValueError, OSError) as exc:
        typer.echo("invalid_input_or_configuration", err=True)
        raise SystemExit(2) from exc


@app.command("evaluate-robustness")
def evaluate_robustness(
    config: Annotated[Path, typer.Option(exists=True)],
    provider: str = "mock",
    out: Path = Path("artifacts/runs"),
) -> None:
    from verisoc.evaluation.robustness import run_robustness

    typer.echo(str(run_robustness(config, out, provider)))


@datasets.command("convert-evtx")
def convert_windows(
    input: Annotated[Path, typer.Option(exists=True)], out: Annotated[Path, typer.Option()]
) -> None:
    try:
        from verisoc.ingest.evtx import convert_evtx
    except ImportError as exc:
        raise typer.BadParameter("Install optional extra: uv sync --extra evtx") from exc

    typer.echo(str(convert_evtx(input, out)))


@cases.command("open-window")
def open_case_window(
    start: Annotated[str, typer.Option()],
    end: Annotated[str, typer.Option()],
    dataset: str = "demo",
    tenant: str = "demo-a",
    db: Path = Path("artifacts/demo/verisoc.db"),
) -> None:
    from verisoc.investigation.evidence_pipeline import CaseWindow, open_window

    request = CaseWindow.model_validate(dict(dataset_id=dataset, start_at=start, end_at=end))
    with database(db).scope(demo_tenant(tenant)) as repo:
        typer.echo(open_window(repo, request).model_dump_json(indent=2))


@cases.command("facts")
def list_verified_facts(
    case_id: Annotated[UUID, typer.Option()],
    tenant: str = "demo-a",
    db: Path = Path("artifacts/demo/verisoc.db"),
    offset: int = 0,
) -> None:
    from verisoc.evidence.registry import EvidenceRegistry
    from verisoc.investigation.evidence_pipeline import FactRouter

    with database(db).scope(demo_tenant(tenant)) as repo:
        registry = EvidenceRegistry(repo, repo.get_case(case_id))
        typer.echo(FactRouter(registry).packet(offset=offset).model_dump_json(indent=2))


@cases.command("investigate-v04")
def investigate_v04(
    case_id: Annotated[UUID, typer.Option()],
    tenant: str = "demo-a",
    db: Path = Path("artifacts/demo/verisoc.db"),
    provider: str = "mock",
) -> None:
    from verisoc.investigation.evidence_pipeline import investigate_evidence, render_evidence

    if provider != "mock":
        raise typer.BadParameter("v0.4 exposes only the offline fact selector")
    with database(db).scope(demo_tenant(tenant)) as repo:
        typer.echo(render_evidence(investigate_evidence(repo, repo.get_case(case_id))))


@app.command("validate-reviews")
def validate_reviews(
    manifest: Annotated[Path, typer.Option(exists=True, readable=True)],
    contamination: Annotated[Path, typer.Option(exists=True, readable=True)],
) -> None:
    from verisoc.evaluation.review_gate import ReviewManifest, check_review_gate

    if manifest.stat().st_size > 2_000_000 or contamination.stat().st_size > 100_000:
        raise typer.BadParameter("Review input size exceeded")
    families = json.loads(contamination.read_text())
    if not isinstance(families, list) or not all(isinstance(f, str) for f in families):
        raise typer.BadParameter("Expected a list of contaminated family IDs")
    result = check_review_gate(
        ReviewManifest.model_validate_json(manifest.read_text()), set(families)
    )
    typer.echo(json.dumps(result, indent=2, sort_keys=True))
