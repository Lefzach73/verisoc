import random
from collections import defaultdict
from typing import Any

from verisoc.evaluation.metrics import aggregate, percentile


def paired_bootstrap(
    rows_a: list[dict[str, Any]],
    rows_b: list[dict[str, Any]],
    metric: str,
    seed: int,
    replicates: int = 2000,
) -> dict[str, Any]:
    a = {r["scenario_id"]: r for r in rows_a}
    b = {r["scenario_id"]: r for r in rows_b}
    if not a or len(a) != len(rows_a) or len(b) != len(rows_b):
        raise ValueError("Nonempty unique paired cases required")
    if set(a) != set(b):
        raise ValueError("Paired cases required")
    families: dict[str, list[str]] = defaultdict(list)
    for case_id, row in a.items():
        if row["family"] != b[case_id]["family"]:
            raise ValueError("Family mismatch")
        families[row["family"]].append(case_id)
    keys = sorted(families)
    rng = random.Random(seed)
    differences: list[float] = []
    for _ in range(replicates):
        ids = [cid for f in rng.choices(keys, k=len(keys)) for cid in families[f]]
        ma, mb = (
            aggregate([a[cid] for cid in ids])[metric],
            aggregate([b[cid] for cid in ids])[metric],
        )
        if ma is not None and mb is not None:
            differences.append(ma - mb)
    observed_a, observed_b = aggregate(rows_a)[metric], aggregate(rows_b)[metric]
    return {
        "unit": "incident_family",
        "replicates": replicates,
        "valid_replicates": len(differences),
        "seed": seed,
        "metric": metric,
        "difference_a_minus_b": observed_a - observed_b
        if observed_a is not None and observed_b is not None
        else None,
        "ci95": [percentile(differences, 0.025), percentile(differences, 0.975)],
    }


def hypothesis_intervals(
    full: list[dict[str, Any]],
    baseline: list[dict[str, Any]],
    seed: int,
    replicates: int = 2000,
) -> dict[str, Any]:
    """Predeclared H1 ratio contrast and H2 noninferiority; no human efficacy inference."""
    paired_bootstrap(full, baseline, "coverage", seed, replicates=1)
    a = {r["scenario_id"]: r for r in full}
    b = {r["scenario_id"]: r for r in baseline}
    families: dict[str, list[str]] = defaultdict(list)
    for cid, row in a.items():
        if row["proposal_fingerprint"] != b[cid]["proposal_fingerprint"]:
            raise ValueError("Hypothesis test requires identical paired candidate proposals")
        families[row["family"]].append(cid)
    keys = sorted(families)
    rng = random.Random(seed)
    h1, h2 = [], []
    for _ in range(replicates):
        ids = [cid for f in rng.choices(keys, k=len(keys)) for cid in families[f]]
        ma, mb = aggregate([a[i] for i in ids]), aggregate([b[i] for i in ids])
        ua, ub = ma["unsupported_factual_claim_rate"], mb["unsupported_factual_claim_rate"]
        if ua is not None and ub is not None:
            h1.append(ua - 0.5 * ub)
        if ma["recall"] is not None and mb["recall"] is not None:
            h2.append(ma["recall"] - mb["recall"])
    ma, mb = aggregate(full), aggregate(baseline)
    h1_ci = [percentile(h1, 0.025), percentile(h1, 0.975)]
    h2_ci = [percentile(h2, 0.025), percentile(h2, 0.975)]
    active = bool(ma["coverage"] and mb["recall"])
    h1_evaluable = bool(mb["emitted_unsupported_claims"] and ma["emitted_factual_claims"])
    return {
        "scope": "constrained_raw_predicate_proxy_with_procedural_case_labels",
        "independent_scientific_confirmation": False,
        "cluster_unit": "mechanism_family",
        "clusters": len(keys),
        "replicates": replicates,
        "H1": {
            "contrast": "B3 unsupported rate minus 0.5 * B2 unsupported rate; target <= 0",
            "ci95": h1_ci,
            "valid_replicates": len(h1),
            "status": "inconclusive_zero_baseline_errors_or_no_emitted_facts"
            if not h1_evaluable
            else "supported_on_proxy"
            if h1_ci[1] is not None and h1_ci[1] <= 0
            else "not_established_on_proxy",
        },
        "H2": {
            "contrast": "B3 recall minus B2 recall; noninferiority margin -0.05",
            "ci95": h2_ci,
            "valid_replicates": len(h2),
            "status": "inconclusive_zero_recall_or_coverage"
            if not active
            else "supported_on_procedural_labels"
            if h2_ci[0] is not None and h2_ci[0] >= -0.05
            else "not_established_on_procedural_labels",
        },
        "limitations": "Few clusters, stipulated intent, no independent human claim judgments. "
        "Observed operational labels are not proof of real compromise.",
    }
