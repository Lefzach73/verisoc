"""Frozen matched mock matrix with scoped context. No paid provider or label access."""

import json
import time
from pathlib import Path
from typing import Any
from uuid import UUID

from verisoc.core.ids import stable_id
from verisoc.core.models import CandidateReport, CanonicalEvent, Case
from verisoc.core.provenance import digest, json_hash
from verisoc.detection.rules import detect
from verisoc.evaluation.baseline import run_arm
from verisoc.evaluation.v05_context_inputs import StudyOracle, context_bundles, visible_context
from verisoc.evaluation.v05_intake import IntakeManifest
from verisoc.evaluation.v05_study import (
    StudyPlan,
    freeze_identity,
    json_bytes,
    verify_study,
    write_new,
)
from verisoc.evidence.registry import EvidenceRegistry
from verisoc.ingest.importer import import_jsonl
from verisoc.investigation.evidence_pipeline import FactSelection, FactView, view
from verisoc.investigation.pipeline import Attempt
from verisoc.investigation.tool_router import project
from verisoc.llm.base import Budget
from verisoc.llm.mock import MockProvider, observed
from verisoc.storage.repository import Database
from verisoc.v05.triage import triage

MODEL_ID = "matched-engineering-smoke-1"


class MatchedMockMetadata(MockProvider):
    model_id = MODEL_ID


def common_proposal(
    case: Case,
    events: list[CanonicalEvent],
    facts: list[FactView],
    context_records: list[dict[str, Any]] | None = None,
) -> tuple[CandidateReport, FactSelection]:
    alert_ids = set(case.alert.event_ids) if case.alert else set()
    indicator_ids = {eid for fact in facts if fact.priority > 0 for eid in fact.source_event_ids}
    ordered = sorted(
        events,
        key=lambda e: (
            e.event_id not in alert_ids,
            e.event_id not in indicator_ids,
            e.occurred_at,
            str(e.event_id),
        ),
    )
    candidate = CandidateReport(
        claims=tuple(observed(e) for e in ordered[:32]),
        proposed_verdict="malicious" if any(f.priority > 0 for f in facts) else "needs_review",
    )
    ids = tuple(f.fact_id for f in facts if f.priority > 0)[:32]
    return candidate, FactSelection(
        fact_ids=ids, observation="Matched offline proposal, no LLM ability claim."
    )


def run_frozen_mock(study: Path, code_root: Path, out: Path) -> dict[str, Any]:
    verify_study(study, code_root)
    plan = StudyPlan.model_validate_json((study / "plan.json").read_text())
    intake = IntakeManifest.model_validate_json((study / "intake.json").read_text())
    validation = json.loads((study / "validation.json").read_text())
    if plan.model_id != MODEL_ID or plan.model_revision != "1.0":
        raise ValueError("Frozen model does not match the implemented offline proposer")

    out.mkdir(parents=True, exist_ok=False)
    details = {c["case_id"]: c for c in validation["cases"]}
    rows = []
    candidates = []
    packets = []
    contexts = []
    db = Database("sqlite:///:memory:")
    try:
        for item in intake.cases:
            case_rows: list[dict[str, Any]] = []
            preparation_started = time.perf_counter()
            try:
                with db.scope(item.tenant_id) as repo:
                    content = (study / "inputs" / item.event_file).read_bytes()
                    oracle = StudyOracle(content, item.tenant_id, item.dataset_id)
                    import_jsonl(repo, content, item.dataset_id)
                    records = [
                        repo.get_event(eid) for eid in map(UUID, details[item.case_id]["event_ids"])
                    ]
                    records.sort(key=lambda e: (e.occurred_at, str(e.event_id)))
                    begin, end = records[0].occurred_at, records[-1].occurred_at
                    alerts = [
                        c.alert
                        for c in detect(repo, item.dataset_id)
                        if c.alert and c.start_at >= begin and c.end_at <= end
                    ]
                    alert = (
                        max(alerts, key=lambda a: (a.severity == "high", a.rule_id))
                        if alerts
                        else None
                    )
                    case = Case(
                        case_id=stable_id("v05-study-case", plan.study_id, item.case_id),
                        tenant_id=repo.tenant,
                        dataset_id=item.dataset_id,
                        event_ids=tuple(e.event_id for e in records),
                        start_at=begin,
                        end_at=end,
                        alert=alert,
                    )
                    repo.put_case(case)
                    bundles = (
                        context_bundles(study / "inputs", intake, item)
                        if (plan.context_condition == "with_context")
                        else ()
                    )
                    scoped_context = [
                        record
                        for bundle in bundles
                        for record in visible_context(bundle, set(case.event_ids))
                    ]
                    contexts.append(dict(case_id=item.case_id, records=scoped_context))
                    registry = EvidenceRegistry(repo, case)
                    facts = [view(f) for f in registry.facts.values()]
                    packet = dict(
                        case=case.model_dump(mode="json"),
                        events=[project(e) for e in records],
                        offered_facts=[f.model_dump(mode="json") for f in facts],
                        recorded_context=scoped_context,
                        budget=plan.model_dump(
                            mode="json",
                            include={"max_tool_calls", "max_selected_facts", "max_case_events"},
                        ),
                    )
                    opportunity = json_hash(packet)
                    packets.append(
                        dict(case_id=item.case_id, opportunity_sha256=opportunity, packet=packet)
                    )
                    proposal_error = None
                    proposal = CandidateReport(claims=(), proposed_verdict="needs_review")
                    selection = FactSelection(fact_ids=())
                    try:
                        proposal, selection = common_proposal(case, records, facts, scoped_context)
                        proposal = CandidateReport.model_validate(proposal.model_dump(mode="json"))
                        selection = FactSelection.model_validate_json(selection.model_dump_json())

                    except Exception:
                        proposal_error = "mock_proposal_failure"
                    selection_error = (
                        "unoffered_fact_id"
                        if not set(selection.fact_ids) <= set(registry.facts)
                        else None
                    )
                    shared = json_hash(
                        dict(
                            candidate=proposal.model_dump(mode="json"),
                            selection=selection.model_dump(mode="json"),
                        )
                    )
                    candidates.append(
                        dict(
                            case_id=item.case_id,
                            shared_proposal_sha256=shared,
                            candidate=proposal.model_dump(mode="json"),
                            selection=selection.model_dump(mode="json"),
                            error=proposal_error,
                        )
                    )
                    preparation_ms = (time.perf_counter() - preparation_started) * 1000
                    attempt = Attempt(
                        proposal=proposal,
                        limits=(proposal_error,) if proposal_error else (),
                        raw_outputs=[json.dumps(candidates[-1])],
                        context=[project(e) for e in records],
                    )
                    for arm in plan.arms:
                        started = time.perf_counter()
                        row: dict[str, Any] = dict(
                            case_id=item.case_id,
                            family_id=item.family_id,
                            partition=item.partition,
                            context_condition=plan.context_condition,
                            preparation_ms=preparation_ms,
                            arm=arm,
                            model_id=MODEL_ID
                            if arm not in ("B0", "deterministic-verified")
                            else "none",
                            evidence_opportunity_sha256=opportunity,
                            shared_proposal_sha256=shared
                            if arm in ("B2", "B3", "B3-hybrid-v0.5")
                            else None,
                            triage_flag=False,
                            incident_verdict="needs_review",
                            emitted_fact_count=0,
                            unsupported_facts=0,
                            reasons=[],
                            error=None,
                            usd=0,
                        )
                        try:
                            if arm in ("B0", "B2", "B3"):
                                result = run_arm(
                                    repo,
                                    case,
                                    MatchedMockMetadata(),
                                    Budget(),
                                    arm,
                                    freeze_identity(study),
                                    plan.seed,
                                    replay=None if arm == "B0" else attempt,
                                )
                                row.update(
                                    triage_flag=result.verdict == "malicious",
                                    incident_verdict=result.verdict,
                                    emitted_fact_count=len(result.emitted),
                                    unsupported_facts=sum(
                                        not oracle.supports(case, d.candidate)
                                        for d in result.emitted
                                    ),
                                    reasons=list(result.attempt.limits),
                                    error=proposal_error if arm in ("B2", "B3") else None,
                                )
                            elif arm == "B3-hybrid-v0.5" and (proposal_error or selection_error):
                                row.update(
                                    reasons=[proposal_error or selection_error],
                                    error=proposal_error or selection_error,
                                )
                            else:
                                result_v05 = triage(
                                    repo,
                                    case,
                                    bundles,
                                    selected_fact_ids=selection.fact_ids
                                    if arm == "B3-hybrid-v0.5"
                                    else None,
                                )
                                row.update(
                                    triage_flag=result_v05.triage_flag,
                                    incident_verdict=result_v05.incident_verdict,
                                    emitted_fact_count=len(result_v05.verified_observations)
                                    + len(result_v05.indicator_evidence)
                                    + len(result_v05.verified_context),
                                    unsupported_facts=sum(
                                        not oracle.supports_fact(case, registry.facts[f.fact_id])
                                        for f in (
                                            *result_v05.verified_observations,
                                            *result_v05.indicator_evidence,
                                        )
                                    )
                                    + sum(
                                        not oracle.supports_context(
                                            case,
                                            registry.facts[c.explained_fact_id],
                                            c,
                                            next(
                                                b
                                                for b in bundles
                                                if b.authority.source_id == c.source_id
                                            ),
                                        )
                                        for c in result_v05.verified_context
                                    ),
                                    omitted_indicators=len(result_v05.omitted_indicator_ids),
                                    context_facts=len(result_v05.verified_context),
                                    reasons=list(result_v05.reason_codes),
                                )
                        except Exception:
                            row.update(error="pipeline_failure", reasons=["pipeline_failure"])
                        row["duration_ms"] = (time.perf_counter() - started) * 1000
                        row["total_duration_ms"] = preparation_ms + row["duration_ms"]
                        case_rows.append(row)
            except Exception:
                case_rows = []
                for arm in plan.arms:
                    case_rows.append(
                        dict(
                            case_id=item.case_id,
                            family_id=item.family_id,
                            partition=item.partition,
                            context_condition=plan.context_condition,
                            arm=arm,
                            evidence_opportunity_sha256=None,
                            shared_proposal_sha256=None,
                            triage_flag=False,
                            incident_verdict="needs_review",
                            emitted_fact_count=0,
                            unsupported_facts=0,
                            reasons=["input_or_pipeline_failure"],
                            error="input_or_pipeline_failure",
                            duration_ms=None,
                            preparation_ms=None,
                            total_duration_ms=None,
                            usd=0,
                        )
                    )
            rows.extend(case_rows)
    finally:
        db.engine.dispose()
    pairs = {c.case_id: [r for r in rows if r["case_id"] == c.case_id] for c in intake.cases}
    if any(
        len(rs) != len(plan.arms) or {r["arm"] for r in rs} != set(plan.arms)
        for rs in pairs.values()
    ):
        raise ValueError("Paired denominator invariant failed")
    summary = dict(
        validity="smoke_only_unscored",
        cases=len(intake.cases),
        arm_rows=len(rows),
        failed_rows=sum(r["error"] is not None for r in rows),
        human_labels_available=False,
        H1="not_evaluated_no_independent_claim_judgments",
        H2="not_evaluated_no_independent_incident_labels",
        fpr="undefined_no_adjudicated_benign_denominator",
        new_provider_cost_usd=0,
        comparison_notes=[
            "B2 and original B3 replay the exact same proposal.",
            "Shared authorized event universe; B0 retains original rule semantics.",
            "Hybrid flags use selected verified IDs; omitted indicators remain visible.",
            "The deterministic selector exposes the absence of demonstrated LLM gains.",
            "Legacy malicious verdicts are predictions, not independently confirmed attacks.",
        ],
    )
    for name, data in [
        ("rows.json", rows),
        ("proposals.json", candidates),
        ("packets.json", packets),
        ("context.json", contexts),
        ("summary.json", summary),
    ]:
        write_new(out / name, json_bytes(data))
    manifest = dict(
        schema_version="matched-run-1.1",
        study_manifest_sha256=freeze_identity(study),
        context_condition=plan.context_condition,
        status="complete_with_failures" if summary["failed_rows"] else "complete",
        provider="mock",
        model_id=MODEL_ID,
        model_revision="1.0",
        validity="smoke_only",
        output_sha256={p.name: digest(p.read_bytes()) for p in out.iterdir() if p.is_file()},
        exact_case_denominator=len(intake.cases),
        new_provider_cost_usd=0,
    )
    write_new(out / "manifest.json", json_bytes(manifest))
    return summary
