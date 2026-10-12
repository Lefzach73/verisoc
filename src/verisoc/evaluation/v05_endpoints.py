"""Partition-local descriptive endpoints and fixed numerical screens, never certification."""

import random
from collections import Counter, defaultdict
from typing import Any

from verisoc.evaluation.metrics import percentile, ratio
from verisoc.evaluation.triage import paired_recall_interval, triage_metrics
from verisoc.evaluation.v05_statistics import fpr_upper
from verisoc.evaluation.v05_study import StudyPlan


def rate_interval(
    data: list[dict[str, Any]], reference: list[dict[str, Any]], plan: StudyPlan
) -> dict[str, Any]:
    """Paired family resampling of micro-averaged unsupported typed-fact rates."""
    ref = {r["case_id"]: r for r in reference}
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in data:
        groups[row["family_id"]].append(row)

    def rates(sample: list[dict[str, Any]]) -> tuple[float | None, float | None]:
        other = [ref[r["case_id"]] for r in sample]
        return tuple(  # type: ignore[return-value]
            ratio(
                sum(r["unsupported_facts"] for r in rows),
                sum(r["emitted_fact_count"] for r in rows),
            )
            for rows in (sample, other)
        )

    rng = random.Random(plan.seed)
    keys = sorted(groups)
    differences, ratios = [], []
    for _ in range(plan.bootstrap_replicates if keys else 0):
        sample = [r for family in rng.choices(keys, k=len(keys)) for r in groups[family]]
        a, b = rates(sample)
        if a is not None and b is not None:
            differences.append(a - b)
            if b > 0:
                ratios.append(a / b)
    a, b = rates(data)
    return dict(
        endpoint="raw typed predicates; not human narrative support judgments",
        families=len(keys),
        seed=plan.seed,
        replicates=plan.bootstrap_replicates,
        difference=a - b if a is not None and b is not None else None,
        ci95=[percentile(differences, 0.025), percentile(differences, 0.975)],
        valid_replicates=len(differences),
        rate_ratio=a / b if a is not None and b is not None and b > 0 else None,
        ratio_ci95=[percentile(ratios, 0.025), percentile(ratios, 0.975)],
        valid_ratio_replicates=len(ratios),
    )


def summarize_partition(
    by_arm: dict[str, list[dict[str, Any]]], labels: dict[str, str], plan: StudyPlan
) -> dict[str, Any]:
    summaries = {}
    paired = []
    for arm, data in by_arm.items():
        points = [
            dict(
                scenario_id=r["case_id"],
                family=r["family_id"],
                gold_verdict=labels[r["case_id"]],
                flagged=r["triage_flag"],
                incident=r["incident_verdict"] == "malicious",
            )
            for r in data
        ]
        triage = triage_metrics(points)
        facts = sum(r["emitted_fact_count"] for r in data)
        unsupported = sum(r["unsupported_facts"] for r in data)
        summaries[arm] = dict(
            triage=triage,
            incident_predictions=triage_metrics(points, "incident"),
            benign_fpr_counts=dict(
                numerator=triage["benign_false_positives"], denominator=triage["benign_cases"]
            ),
            recall_counts=dict(
                numerator=triage["true_positives"], denominator=triage["malicious_labeled_cases"]
            ),
            benign_fpr_upper_95=fpr_upper(triage["benign_false_positives"], triage["benign_cases"]),
            emitted_typed_facts=facts,
            unsupported_typed_facts=unsupported,
            unsupported_predicate_rate=ratio(unsupported, facts),
            unsupported_denominator_note="Raw predicate proxy; human narrative judgments absent.",
            verified_fact_coverage=ratio(sum(r["emitted_fact_count"] > 0 for r in data), len(data))
            if arm in ("B3", "B3-hybrid-v0.5", "deterministic-verified")
            else None,
            incident_verdict_coverage=ratio(
                sum(r["incident_verdict"] != "needs_review" for r in data), len(data)
            ),
            abstention_counts=dict(
                incident=sum(r["incident_verdict"] == "needs_review" for r in data),
                triage=sum(not r["triage_flag"] for r in data),
            ),
            reason_counts=dict(Counter(reason for r in data for reason in r["reasons"])),
            omitted_indicators=sum(r.get("omitted_indicators", 0) for r in data),
            failed_cases=sum(r["error"] is not None for r in data),
            latency_p50_ms=percentile(
                [r["duration_ms"] for r in data if r["duration_ms"] is not None], 0.5
            ),
            latency_p95_ms=percentile(
                [r["duration_ms"] for r in data if r["duration_ms"] is not None], 0.95
            ),
            total_latency_p50_ms=percentile(
                [r["total_duration_ms"] for r in data if r.get("total_duration_ms") is not None],
                0.5,
            ),
            total_latency_p95_ms=percentile(
                [r["total_duration_ms"] for r in data if r.get("total_duration_ms") is not None],
                0.95,
            ),
            new_usd=sum(r["usd"] for r in data),
            risk_coverage_curve=dict(
                policy=(
                    "Frozen binary policy: abstain-all and deployed operating point only; "
                    "no threshold search."
                ),
                points=[
                    dict(policy="abstain_all", coverage=0 if data else None, selective_risk=None),
                    dict(
                        policy="frozen_policy",
                        coverage=triage["triage_coverage"],
                        selective_risk=triage["selective_risk_decidable"],
                    ),
                ],
            ),
        )
    for reference_arm in ("B2", "B0", "deterministic-verified"):
        reference = {r["case_id"]: r for r in by_arm[reference_arm]}
        for arm, data in by_arm.items():
            if arm == reference_arm:
                continue
            pairs = [
                dict(
                    scenario_id=r["case_id"],
                    family=r["family_id"],
                    gold_verdict=labels[r["case_id"]],
                    triage_first=r["triage_flag"],
                    triage_second=reference[r["case_id"]]["triage_flag"],
                    incident_first=r["incident_verdict"] == "malicious",
                    incident_second=reference[r["case_id"]]["incident_verdict"] == "malicious",
                )
                for r in data
            ]

            def interval(first: str, second: str, values: list[dict[str, Any]]) -> dict[str, Any]:
                if not values:
                    return dict(
                        difference=None,
                        ci95=[None, None],
                        families=0,
                        valid_replicates=0,
                        replicates=plan.bootstrap_replicates,
                    )
                return paired_recall_interval(
                    values, first, second, seed=plan.seed, replicates=plan.bootstrap_replicates
                )

            paired.append(
                dict(
                    arm=arm,
                    reference=reference_arm,
                    triage=interval("triage_first", "triage_second", pairs),
                    original_H2=interval("incident_first", "incident_second", pairs),
                    typed_predicates=rate_interval(data, by_arm[reference_arm], plan),
                )
            )
    return dict(
        cases=len(by_arm["B2"]),
        families=len({r["family_id"] for r in by_arm["B2"]}),
        arms=summaries,
        paired=paired,
    )


def numerical_screens(holdout: dict[str, Any], plan: StudyPlan) -> dict[str, Any]:
    """Evaluated simultaneously; a numerical PASS never overrides external validity gates."""
    hybrid = holdout["arms"]["B3-hybrid-v0.5"]
    pairs = {p["reference"]: p for p in holdout["paired"] if p["arm"] == "B3-hybrid-v0.5"}

    def screen(value: Any, passed: bool, definition: str) -> dict[str, Any]:
        return dict(
            status="BLOCKED" if value is None else "PASS" if passed else "FAIL",
            value=value,
            definition=definition,
        )

    fpr = hybrid["benign_fpr_upper_95"]
    coverage = hybrid["triage"]["triage_coverage"]
    h2 = pairs["B2"]["original_H2"]["ci95"][0]
    gain = pairs["B0"]["triage"]["ci95"][0]
    typed = pairs["B2"]["typed_predicates"]["ci95"][1]
    h1 = pairs["B2"]["typed_predicates"]["ratio_ci95"][1]
    checks = dict(
        unsupported_typed_rate_vs_B2=screen(
            typed,
            typed is not None and typed <= 0,
            "Upper paired family interval of rate difference <= 0; nonempty fact denominators.",
        ),
        H1_typed_proxy=screen(
            h1,
            h1 is not None and h1 <= plan.H1_rate_ratio,
            "Upper interval of typed-fact rate ratio <= 0.5; does not establish narrative H1.",
        ),
        triage_recall_gain_vs_B0=screen(
            gain, gain is not None and gain > 0, "Lower paired family recall-difference bound > 0."
        ),
        benign_FPR=screen(
            fpr,
            fpr is not None and fpr <= plan.maximum_fpr_upper,
            "One-sided 95% binomial upper bound <= 0.05; independence is externally verified.",
        ),
        nonzero_triage=screen(
            coverage,
            coverage is not None and coverage >= plan.minimum_triage_coverage,
            "Triage coverage >= 0.20.",
        ),
        original_H2=screen(
            h2,
            h2 is not None
            and h2 >= plan.H2_margin
            and (hybrid["incident_verdict_coverage"] or 0) > 0,
            "Lower incident recall-difference bound vs B2 >= -0.05 "
            "AND nonzero incident verdict coverage.",
        ),
        sample_design=screen(
            holdout["cases"] if holdout["cases"] else None,
            holdout["cases"] >= 200
            and holdout["families"] >= 20
            and hybrid["triage"]["benign_cases"] >= 100,
            "At least 200 holdout cases, 20 families, 100 benign labels; "
            "power/independence still require custodian review.",
        ),
    )
    return dict(
        scope="holdout-only numerical screens; not scientific acceptance",
        checks=checks,
        simultaneous_status="FAIL"
        if any(c["status"] == "FAIL" for c in checks.values())
        else "BLOCKED"
        if any(c["status"] == "BLOCKED" for c in checks.values())
        else "PASS",
        scientific_status="BLOCKED",
        external_gates=[
            "independent data, source permission, power analysis and preregistration",
            "authentic human identities, blinding and claim-support judgments",
            "real model execution authorization and matched prospective results",
            "bounded safety results require separate evidence; metrics cannot certify safety",
        ],
    )
