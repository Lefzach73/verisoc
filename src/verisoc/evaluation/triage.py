"""Explicit endpoints for development triage; no implication of incident confirmation."""

import random
from collections import Counter, defaultdict
from typing import Any

from verisoc.evaluation.metrics import percentile, ratio


def triage_metrics(rows: list[dict[str, Any]], flag: str = "flagged") -> dict[str, Any]:
    positive = [r for r in rows if r["gold_verdict"] == "malicious"]
    benign = [r for r in rows if r["gold_verdict"] == "benign"]
    selected = [r for r in rows if r[flag]]
    tp = sum(r[flag] for r in positive)
    fp = sum(r[flag] for r in benign)
    ambiguous = sum(r["gold_verdict"] not in ("malicious", "benign") for r in selected)
    families = sorted({r["family"] for r in positive})
    recalls = [
        sum(r[flag] for r in positive if r["family"] == f) / sum(r["family"] == f for r in positive)
        for f in families
    ]
    return dict(
        cases=len(rows),
        malicious_labeled_cases=len(positive),
        benign_cases=len(benign),
        flagged=len(selected),
        true_positives=tp,
        benign_false_positives=fp,
        ambiguous_flagged=ambiguous,
        recall=ratio(tp, len(positive)),
        benign_fpr=ratio(fp, len(benign)),
        precision_on_decidable=ratio(tp, tp + fp),
        precision_ambiguous_as_negative=ratio(tp, len(selected)),
        triage_coverage=ratio(len(selected), len(rows)),
        selective_risk_decidable=ratio(fp, tp + fp),
        family_macro_recall=ratio(sum(recalls), len(recalls)),
        independent_family_claim=False,
        labeled_positive_families=len(families),
        utility_tp_minus_benign_fp=tp - fp,
    )


def risk_curve(rows: list[dict[str, Any]], max_benign_fpr: float = 0.05) -> dict[str, Any]:
    if not 0 <= max_benign_fpr <= 1:
        raise ValueError("Invalid FPR bound")
    curve = []
    for threshold in (1, 2, 3):
        points = [{**r, "flagged": r["priority"] >= threshold} for r in rows]
        curve.append(dict(threshold=threshold, **triage_metrics(points)))
    feasible = [
        r
        for r in curve
        if r["flagged"] and r["benign_fpr"] is not None and r["benign_fpr"] <= max_benign_fpr
    ]
    return dict(
        scope="development-only empirical curve, no statistical risk guarantee",
        maximum_benign_fpr=max_benign_fpr,
        curve=curve,
        selected_threshold=max(feasible, key=lambda r: r["recall"] or 0)["threshold"]
        if feasible
        else None,
        calibration_status="empirical_candidate_only"
        if feasible
        else "no_nonempty_feasible_policy",
    )


def paired_recall_interval(
    rows: list[dict[str, Any]], first: str, second: str, seed: int = 404, replicates: int = 2000
) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not rows or len({r["scenario_id"] for r in rows}) != len(rows):
        raise ValueError("Nonempty unique paired cases required")
    for row in rows:
        groups[row["family"]].append(row)
    rng = random.Random(seed)
    keys = sorted(groups)
    differences = []
    for _ in range(replicates):
        sample = [r for f in rng.choices(keys, k=len(keys)) for r in groups[f]]
        a, b = triage_metrics(sample, first)["recall"], triage_metrics(sample, second)["recall"]
        if a is not None and b is not None:
            differences.append(a - b)
    a, b = triage_metrics(rows, first)["recall"], triage_metrics(rows, second)["recall"]
    return dict(
        scope="exploratory family-clustered diagnostic; not independent validation",
        first=first,
        second=second,
        families=len(keys),
        seed=seed,
        replicates=replicates,
        valid_replicates=len(differences),
        difference=a - b if a is not None and b is not None else None,
        ci95=[percentile(differences, 0.025), percentile(differences, 0.975)],
    )


def arm_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    emitted = sum(r["emitted_facts"] for r in rows)
    unsupported = sum(r["unsupported_facts"] for r in rows)
    return dict(
        **triage_metrics(rows),
        emitted_facts=emitted,
        unsupported_facts=unsupported,
        unsupported_predicate_rate=ratio(unsupported, emitted),
        verified_fact_coverage=ratio(sum(r["verified_facts"] > 0 for r in rows), len(rows)),
        incident_verdict_coverage=ratio(
            sum(r["verdict"] != "needs_review" for r in rows), len(rows)
        ),
        incident_verdict_recall=ratio(
            sum(r["gold_verdict"] == "malicious" and r["verdict"] == "malicious" for r in rows),
            sum(r["gold_verdict"] == "malicious" for r in rows),
        ),
        reason_counts=dict(Counter(reason for r in rows for reason in r["reasons"])),
        latency_p50_ms=percentile([r["duration_ms"] for r in rows], 0.5),
        latency_p95_ms=percentile([r["duration_ms"] for r in rows], 0.95),
        provider_timeouts=0,
        provider_calls=0,
        new_provider_cost_usd=0,
    )
