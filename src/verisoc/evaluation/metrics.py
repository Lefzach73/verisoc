import math
from typing import Any


def ratio(num: int | float, den: int | float) -> float | None:
    return num / den if den else None


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    pos = (len(values) - 1) * fraction
    low, high = math.floor(pos), math.ceil(pos)
    return values[low] * (high - pos) + values[high] * (pos - low) if high != low else values[low]


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    tp = sum(r["gold_verdict"] == "malicious" and r["verdict"] == "malicious" for r in rows)
    fp = sum(r["gold_verdict"] != "malicious" and r["verdict"] == "malicious" for r in rows)
    fn = sum(r["gold_verdict"] == "malicious" and r["verdict"] != "malicious" for r in rows)
    emitted = sum(r["emitted_factual"] for r in rows)
    unsupported = sum(r["emitted_unsupported"] for r in rows)
    cited = sum(r["citation_count"] for r in rows)
    matched = sum(r["gold_citation_matches"] for r in rows)
    gold_cites = sum(r["gold_citation_count"] for r in rows)
    return {
        "cases": n,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positives_per_100": ratio(100 * fp, n),
        "coverage": ratio(sum(r["verdict"] != "needs_review" for r in rows), n),
        "abstention": ratio(sum(r["verdict"] == "needs_review" for r in rows), n),
        "emitted_factual_claims": emitted,
        "emitted_unsupported_claims": unsupported,
        "unsupported_factual_claim_rate": ratio(unsupported, emitted),
        "candidate_claims": sum(r["candidate_count"] for r in rows),
        "candidate_unsupported": sum(r["candidate_unsupported"] for r in rows),
        "citation_precision": ratio(matched, cited),
        "citation_recall": ratio(matched, gold_cites),
        "malformed_or_failed_cases": sum(bool(r["limits"]) for r in rows),
        "latency_p50_ms": percentile([r["duration_ms"] for r in rows], 0.5),
        "latency_p95_ms": percentile([r["duration_ms"] for r in rows], 0.95),
        "tokens_input": sum(r["tokens_input"] for r in rows),
        "tokens_output": sum(r["tokens_output"] for r in rows),
        "estimated_usd": sum(r["estimated_usd"] for r in rows),
        "new_provider_cost_usd": sum(
            r.get("new_provider_cost_usd", r["estimated_usd"]) for r in rows
        ),
        "observation_coverage": ratio(sum(r["emitted_factual"] > 0 for r in rows), n),
    }
