"""Post-review scoring retains original predictions, all failures and separate endpoints."""

import json
from pathlib import Path
from typing import Any

from verisoc.core.provenance import digest, json_hash
from verisoc.evaluation.v05_endpoints import numerical_screens, summarize_partition
from verisoc.evaluation.v05_intake import IntakeManifest
from verisoc.evaluation.v05_review import SubmittedReview, validate_submissions
from verisoc.evaluation.v05_study import (
    StudyPlan,
    freeze_identity,
    json_bytes,
    verify_study,
    write_new,
)


def score_reviewed_run(
    study: Path,
    run: Path,
    forms: Path,
    reviews: tuple[SubmittedReview, ...],
    adjudications: dict[str, dict[str, Any]] | None,
    out: Path,
) -> dict[str, Any]:
    verify_study(study)
    manifest = json.loads((run / "manifest.json").read_text())
    if manifest["study_manifest_sha256"] != freeze_identity(study):
        raise ValueError("Run belongs to a different study freeze")
    required = {"rows.json", "packets.json", "proposals.json", "summary.json"}
    if manifest.get("schema_version") == "matched-run-1.1":
        required.add("context.json")
    if not required <= set(manifest["output_sha256"]):
        raise ValueError("Incomplete run output inventory")
    for name, expected in manifest["output_sha256"].items():
        path = run / name
        if not path.resolve().is_relative_to(run.resolve()) or path.is_symlink():
            raise ValueError("Unsafe result path")
        if digest(path.read_bytes()) != expected:
            raise ValueError("Recorded run changed")
    mapping = json.loads((forms / "custodian-mapping.json").read_text())
    if mapping["study_manifest_sha256"] != freeze_identity(study):
        raise ValueError("Reviewer packets belong to a different study")
    review_result = validate_submissions(forms, reviews, adjudications)
    if review_result["structural_status"] != "PASS":
        raise ValueError("Complete dual review and adjudication required before scoring")
    labels = {
        mapping["mapping"][key]["case_id"]: label
        for key, label in review_result["adjudicated_labels"].items()
    }
    rows = json.loads((run / "rows.json").read_text())
    plan = StudyPlan.model_validate_json((study / "plan.json").read_text())
    intake = IntakeManifest.model_validate_json((study / "intake.json").read_text())
    cases = {c.case_id: c for c in intake.cases}
    if (
        manifest["provider"] != plan.provider
        or manifest["model_id"] != plan.model_id
        or manifest["model_revision"] != plan.model_revision
        or manifest["exact_case_denominator"] != len(cases)
    ):
        raise ValueError("Run model or denominator differs from study plan")
    if set(labels) != set(cases):
        raise ValueError("Reviewer case inventory does not match frozen intake")
    by_arm: dict[str, list[dict[str, Any]]] = {
        arm: [r for r in rows if r["arm"] == arm] for arm in plan.arms
    }
    if set(r["arm"] for r in rows) != set(plan.arms):
        raise ValueError("Unexpected or missing arm")
    for data in by_arm.values():
        if len(data) != len(cases) or {r["case_id"] for r in data} != set(cases):
            raise ValueError("Same cases, including failures, required in every arm")
        for row in data:
            case = cases[row["case_id"]]
            if (
                row["family_id"] != case.family_id
                or row.get("partition", case.partition) != case.partition
            ):
                raise ValueError("Run changed frozen family or partition")
            if row.get("context_condition", plan.context_condition) != plan.context_condition:
                raise ValueError("Run changed frozen context condition")
            if (
                type(row["triage_flag"]) is not bool
                or row["incident_verdict"] not in ("benign", "malicious", "needs_review")
                or type(row["emitted_fact_count"]) is not int
                or type(row["unsupported_facts"]) is not int
                or not 0 <= row["unsupported_facts"] <= row["emitted_fact_count"]
            ):
                raise ValueError("Invalid prediction or fact denominator")

    def indexed_artifacts(name: str) -> dict[str, dict[str, Any]]:
        values = json.loads((run / name).read_text())
        indexed = {p["case_id"]: p for p in values}
        if len(indexed) != len(values) or not set(indexed) <= set(cases):
            raise ValueError("Duplicate or unknown case in packet/proposal inventory")
        return indexed

    packets = indexed_artifacts("packets.json")
    recorded_proposals = indexed_artifacts("proposals.json")
    for packet in packets.values():
        if json_hash(packet["packet"]) != packet["opportunity_sha256"]:
            raise ValueError("Recorded evidence packet hash is inconsistent")
    for proposal in recorded_proposals.values():
        expected_hash = json_hash(
            dict(candidate=proposal["candidate"], selection=proposal["selection"])
        )
        if expected_hash != proposal["shared_proposal_sha256"]:
            raise ValueError("Recorded proposal hash is inconsistent")
    for case_id in cases:
        paired_rows = [r for r in rows if r["case_id"] == case_id]
        opportunities = {r["evidence_opportunity_sha256"] for r in paired_rows}
        if len(opportunities) != 1:
            raise ValueError("Paired evidence opportunities differ")
        opportunity = next(iter(opportunities))
        if opportunity is not None:
            if case_id not in packets or json_hash(packets[case_id]["packet"]) != opportunity:
                raise ValueError("Evidence packet does not match predictions")
        elif any(r["error"] != "input_or_pipeline_failure" for r in paired_rows):
            raise ValueError("Missing evidence opportunity without retained preparation failure")
        proposals = {
            r["shared_proposal_sha256"]
            for r in paired_rows
            if r["arm"] in ("B2", "B3", "B3-hybrid-v0.5")
        }
        if len(proposals) != 1:
            raise ValueError("Matched proposal pairing was changed")
        proposal_hash = next(iter(proposals))
        if proposal_hash is not None:
            if (
                case_id not in recorded_proposals
                or recorded_proposals[case_id]["shared_proposal_sha256"] != proposal_hash
            ):
                raise ValueError("Predictions do not match their recorded proposal")
        elif opportunity is not None:
            raise ValueError("Matched proposal missing for prepared case")
    partitions = {
        partition: summarize_partition(
            {
                arm: [r for r in data if cases[r["case_id"]].partition == partition]
                for arm, data in by_arm.items()
            },
            labels,
            plan,
        )
        for partition in ("development", "calibration", "holdout")
    }
    descriptive = summarize_partition(by_arm, labels, plan)
    result = dict(
        validity="descriptive_only_until_independent_custodian_verification",
        scientific_status="BLOCKED",
        human_authenticity_verified=False,
        primary_partition="holdout",
        partitions=partitions,
        primary=partitions["holdout"],
        numerical_screens=numerical_screens(partitions["holdout"], plan),
        pooled_scope="Descriptive inventory only; never a primary efficacy estimate.",
        arms=descriptive["arms"],
        paired=descriptive["paired"],
        original_reviews=review_result,
        notes=[
            "Source facts, triage and incident predictions are separate endpoints.",
            "No threshold tuning or historical rewriting occurs in scoring.",
            "Family intervals require independent families; synthetic examples are descriptive.",
            "The one-sided binomial FPR bound requires independent benign cases.",
            "Human claim judgments, paid approval and human authenticity are not created.",
        ],
    )
    out.mkdir(parents=True, exist_ok=False)
    write_new(out / "score.json", json_bytes(result))
    write_new(
        out / "manifest.json",
        json_bytes(
            dict(
                study_manifest_sha256=freeze_identity(study),
                run_manifest_sha256=digest((run / "manifest.json").read_bytes()),
                review_mapping_sha256=digest((forms / "custodian-mapping.json").read_bytes()),
                score_sha256=digest((out / "score.json").read_bytes()),
            )
        ),
    )
    return result
