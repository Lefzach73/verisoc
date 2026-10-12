"""Run with python -m verisoc.v05; legacy CLI remains byte-for-byte unchanged."""

from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from verisoc.core.errors import VeriSOCError
from verisoc.core.ids import demo_tenant
from verisoc.storage.repository import Database
from verisoc.v05.context_models import ContextAuthority, ContextBundle
from verisoc.v05.triage import triage

app = typer.Typer(no_args_is_help=True)


@app.callback()
def root() -> None:
    """Offline v0.5 evidence and research tooling."""


@app.command("triage")
def run_triage(
    case_id: Annotated[UUID, typer.Option()],
    db: Annotated[Path, typer.Option(exists=True)],
    tenant: str = "demo-a",
    context: Path | None = None,
    authority: Path | None = None,
) -> None:
    if bool(context) != bool(authority):
        raise typer.BadParameter(
            "Context bytes and independently pinned authority are both required"
        )
    bundles: tuple[ContextBundle, ...] = ()
    if context and authority:
        if context.stat().st_size > 1048576 or authority.stat().st_size > 4096:
            raise typer.BadParameter("Context input size exceeded")
        bundles = (
            ContextBundle(
                content=context.read_bytes(),
                authority=ContextAuthority.model_validate_json(authority.read_text()),
            ),
        )
    database = Database(f"sqlite:///{db}")
    try:
        with database.scope(demo_tenant(tenant)) as repo:
            typer.echo(triage(repo, repo.get_case(case_id), bundles).model_dump_json(indent=2))
    finally:
        database.engine.dispose()


def main() -> None:
    try:
        app()
    except (VeriSOCError, ValueError, OSError) as exc:
        typer.echo("invalid_or_unavailable_evidence", err=True)
        raise SystemExit(2) from exc


@app.command("intake")
def intake_check(
    manifest: Annotated[Path, typer.Option(exists=True)],
    contamination: Annotated[Path, typer.Option(exists=True)],
) -> None:
    import json

    from verisoc.evaluation.v05_intake import ContaminationIndex, IntakeManifest, validate_intake

    source = IntakeManifest.model_validate_json(manifest.read_text())
    index = ContaminationIndex.model_validate_json(contamination.read_text())
    typer.echo(
        json.dumps(validate_intake(manifest.parent, source, index), indent=2, sort_keys=True)
    )


@app.command("freeze-study")
def freeze(
    manifest: Annotated[Path, typer.Option(exists=True)],
    contamination: Annotated[Path, typer.Option(exists=True)],
    plan: Annotated[Path, typer.Option(exists=True)],
    out: Annotated[Path, typer.Option()],
    repo: Path = Path("."),
) -> None:
    import json

    from verisoc.evaluation.v05_intake import ContaminationIndex, IntakeManifest
    from verisoc.evaluation.v05_study import StudyPlan, freeze_study

    result = freeze_study(
        manifest.parent,
        IntakeManifest.model_validate_json(manifest.read_text()),
        ContaminationIndex.model_validate_json(contamination.read_text()),
        StudyPlan.model_validate_json(plan.read_text()),
        repo.resolve(),
        out,
    )
    typer.echo(json.dumps(result, indent=2, sort_keys=True))


@app.command("review-forms")
def forms(
    study: Annotated[Path, typer.Option(exists=True)],
    reviewer_one: Annotated[str, typer.Option()],
    reviewer_two: Annotated[str, typer.Option()],
    out: Annotated[Path, typer.Option()],
) -> None:
    import json

    from verisoc.evaluation.v05_review import export_blind_forms

    typer.echo(json.dumps(export_blind_forms(study, (reviewer_one, reviewer_two), out), indent=2))


@app.command("validate-submissions")
def reviews(
    forms: Annotated[Path, typer.Option(exists=True)],
    submissions: Annotated[Path, typer.Option(exists=True)],
    adjudications: Path | None = None,
    out: Annotated[Path, typer.Option()] = Path("review-result.json"),
) -> None:
    import json

    from pydantic import TypeAdapter

    from verisoc.evaluation.v05_review import (
        SubmittedReview,
        adjudication_template,
        validate_submissions,
    )
    from verisoc.evaluation.v05_study import json_bytes, write_new

    if submissions.stat().st_size > 2000000:
        raise typer.BadParameter("Submission size exceeded")
    values = TypeAdapter(tuple[SubmittedReview, ...]).validate_json(submissions.read_text())
    result = validate_submissions(
        forms, values, json.loads(adjudications.read_text()) if adjudications else None
    )
    write_new(out, json_bytes(result))
    if result["unresolved_disagreements"]:
        adjudication_template(forms, result, out.with_suffix(".adjudication.html"))
    typer.echo(json.dumps({k: v for k, v in result.items() if k != "original_reviews"}, indent=2))


@app.command("run-mock-study")
def run_study(
    study: Annotated[Path, typer.Option(exists=True)],
    out: Annotated[Path, typer.Option()],
    repo: Path = Path("."),
) -> None:
    import json

    from verisoc.evaluation.v05_runner import run_frozen_mock

    typer.echo(json.dumps(run_frozen_mock(study, repo.resolve(), out), indent=2))


@app.command("score-reviewed-run")
def score(
    study: Annotated[Path, typer.Option(exists=True)],
    run: Annotated[Path, typer.Option(exists=True)],
    forms: Annotated[Path, typer.Option(exists=True)],
    submissions: Annotated[Path, typer.Option(exists=True)],
    out: Annotated[Path, typer.Option()],
    adjudications: Path | None = None,
) -> None:
    import json

    from pydantic import TypeAdapter

    from verisoc.evaluation.v05_review import SubmittedReview
    from verisoc.evaluation.v05_scoring import score_reviewed_run

    if submissions.stat().st_size > 2000000:
        raise typer.BadParameter("Submission size exceeded")
    reviews = TypeAdapter(tuple[SubmittedReview, ...]).validate_json(submissions.read_text())
    result = score_reviewed_run(
        study,
        run,
        forms,
        reviews,
        json.loads(adjudications.read_text()) if adjudications else None,
        out,
    )
    typer.echo(
        json.dumps(
            dict(scientific_status=result["scientific_status"], score=str(out / "score.json"))
        )
    )


if __name__ == "__main__":
    main()
