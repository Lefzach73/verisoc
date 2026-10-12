"""Offline post-hoc aggregation of the frozen 2026-10-11 synthetic study.

No model calls, selection of successful cases, or modification of original runs.
"""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

from verisoc.evaluation.metrics import aggregate
from verisoc.evaluation.statistics import paired_bootstrap

FROZEN_SHA = "526cd5deb75e918812d02490032f6017be57336d"
MODELS = {"openai/gpt-4.1-mini", "google/gemini-2.5-flash"}
ARMS = {
    "B0",
    "B1",
    "B2",
    "B3",
    "B3:minus-verifier",
    "B3:minus-evidence-selection",
    "B3:minus-abstention",
    "B3:minus-correlation",
}


def read_run(path):
    manifest = json.loads((path / "manifest.json").read_text())
    if manifest["git"] != {"dirty": False, "sha": FROZEN_SHA}:
        raise ValueError("Unexpected study code provenance")
    if manifest["model"] not in MODELS:
        raise ValueError("Unexpected model")
    for name, expected in manifest["artifact_sha256"].items():
        if Path(name).name != name:
            raise ValueError("Invalid artifact path")
        if hashlib.sha256((path / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Artifact integrity failure: {path.name}/{name}")
    return manifest


def jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def summarize(study, output):
    rows = []
    runs = []
    claims = defaultdict(Counter)
    limits = defaultdict(Counter)
    missing = defaultdict(Counter)
    seen = set()
    for directory in sorted((study / "full").iterdir()):
        if not directory.is_dir():
            continue
        manifest = read_run(directory)
        model = manifest["model"]
        local = jsonl(directory / "case_metrics.jsonl")
        if len(local) != 48:
            raise ValueError("Incomplete shard")
        for row in local:
            key = (model, row["scenario_id"], row["arm"])
            if key in seen:
                raise ValueError("Duplicate study case")
            seen.add(key)
            rows.append({**row, "model": model, "run_id": directory.name})
            limits[model].update(row["limits"])
        for record in jsonl(directory / "claims.jsonl"):
            if record["arm"] == "B3":
                claims[model].update([record["decision"]["reason_code"]])
        for record in jsonl(directory / "predictions.jsonl"):
            if record["arm"] == "B3" and record["vetted_report"]:
                missing[model].update(record["vetted_report"]["missing_evidence"])
        runs.append(
            {
                "run_id": directory.name,
                "manifest_sha256": hashlib.sha256(
                    (directory / "manifest.json").read_bytes()
                ).hexdigest(),
            }
        )
    expected = {
        (model, f"demo-{tenant}-{i:02d}", arm)
        for model in MODELS
        for tenant in ("a", "b")
        for i in range(1, 13)
        for arm in ARMS
    }
    if seen != expected or len(runs) != 8:
        raise ValueError("Expected exactly 384 paired case/arm/model observations")
    models = {}
    for model in sorted(MODELS):
        partitions = {}
        for partition in ("all", "train", "dev", "test"):
            selected = [
                r
                for r in rows
                if r["model"] == model and (partition == "all" or r["partition"] == partition)
            ]
            by_arm = {arm: [r for r in selected if r["arm"] == arm] for arm in sorted(ARMS)}
            partitions[partition] = {
                "arms": {arm: aggregate(items) for arm, items in by_arm.items()},
                "B3_minus_B2": [
                    paired_bootstrap(by_arm["B3"], by_arm["B2"], metric, 20261011, 2000)
                    for metric in ("unsupported_factual_claim_rate", "recall", "coverage")
                ],
            }
        models[model] = {
            "partitions": partitions,
            "B3_predicate_reasons": dict(claims[model]),
            "B3_missing_evidence": dict(missing[model]),
            "all_arm_limits": dict(limits[model]),
        }
    robustness = {}
    for directory in sorted((study / "robustness").iterdir()):
        if directory.is_dir():
            manifest = read_run(directory)
            if manifest["model"] in robustness:
                raise ValueError("Duplicate robustness model")
            robustness[manifest["model"]] = json.loads((directory / "summary.json").read_text())
    if set(robustness) != MODELS or any(r["cases"] != 5 for r in robustness.values()):
        raise ValueError("Incomplete robustness study")
    ledger = json.loads((study / "spend.json").read_text())
    accounting = json.loads((study / "accounting.json").read_text())
    settled = sum(
        (Decimal(r["charged_usd"]) for r in ledger["requests"] if r["state"] == "settled"),
        Decimal(0),
    )
    reserved = sum(
        (Decimal(r["reserved_usd"]) for r in ledger["requests"] if r["state"] != "settled"),
        Decimal(0),
    )
    if settled + reserved > Decimal(ledger["cap_usd"]):
        raise ValueError("Ledger exceeds study cap")
    summary = {
        "study_code_commit": FROZEN_SHA,
        "observations": len(rows),
        "runs": runs,
        "research_validity": "author_labeled_synthetic_pilot_not_independent_efficacy_study",
        "analysis": "Post-hoc aggregation; original case scores retained; failures included",
        "models": models,
        "robustness": robustness,
        "accounting": {
            **accounting,
            "settled_provider_calls_usd": str(settled),
            "unknown_cost_reservations_usd": str(reserved),
            "application_cap_usd": ledger["cap_usd"],
            "ledger_states": dict(Counter(r["state"] for r in ledger["requests"])),
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "study-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    with (output / "study-metrics.csv").open("w") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    with (output / "human-review.csv").open("w") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "scenario_id",
                "reviewer_1_verdict",
                "reviewer_1_supporting_rows",
                "reviewer_2_verdict",
                "reviewer_2_supporting_rows",
                "adjudicated_verdict",
                "adjudicated_supporting_rows",
                "rationale",
                "review_date",
            ]
        )
        writer.writerows(
            [[f"demo-{tenant}-{i:02d}"] + [""] * 8 for tenant in ("a", "b") for i in range(1, 13)]
        )
    lines = [
        "# Real-model synthetic pilot results",
        "",
        "**B3 abstained on every case for both models. Practical triage utility was not "
        "demonstrated. H1–H4 remain unconfirmed.**",
        "",
        f"Frozen source: `{FROZEN_SHA}`. 24 cases × 8 arms × 2 models = 384 observations. "
        "B0 is deterministic and repeated for matched comparisons; these are not 384 "
        "independent incidents. All eight shard manifests and artifact hashes validated.",
        "",
        "## Results including failures",
        "",
        "| Model | Arm | Recall | Coverage | Unsupported predicate rate | Failed/limited | USD |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for model, results in models.items():
        for arm, metrics in results["partitions"]["all"]["arms"].items():

            def percent(value):
                return "undefined" if value is None else f"{100 * value:.1f}%"

            lines.append(
                f"| {model.split('/')[-1]} | {arm} | {percent(metrics['recall'])} | "
                f"{percent(metrics['coverage'])} | "
                f"{percent(metrics['unsupported_factual_claim_rate'])} | "
                f"{metrics['malformed_or_failed_cases']}/24 | "
                f"{metrics['estimated_usd']:.6f} |"
            )
    lines += [
        "",
        "## Interpretation and boundaries",
        "",
        "The support oracle independently rereads raw fixture records. Its metric tests "
        "typed predicate contracts, not human judgments of narrative correctness, intent, "
        "source authenticity or compromise. Unsupported argument names count as unsupported "
        "even when their values may occur in the record. Do not relabel this rate as a "
        "hallucination rate. Full reason counts are in study-summary.json.",
        "",
        "B3's zero emitted unsupported predicates accompanies zero verdict coverage. "
        "B3 versus B2 recall is zero versus zero; that does not establish useful noninferiority. "
        "The deterministic baseline has 75% recall on these author-labeled synthetic cases. "
        "It is the strongest tested triage baseline here, but this is not external validation.",
        "",
        "Only six incident families exist. The prospectively frozen test split contains six "
        "cases in three families; train and dev outputs are diagnostic, not held-out evidence. "
        "Family bootstrap intervals (2,000 draws, fixed seed) and undefined replicate counts "
        "are preserved by partition in JSON. With so few families these intervals are unstable. "
        "Rule and fixture author overlap, one generation per arm/case, provider nondeterminism "
        "and missing independent labels limit every comparison.",
        "",
        "Five inert adversarial cases per model recorded no foreign-data exposure, unsupported "
        "verified claims or unauthorized actions. Each model had one failed/rejected case. "
        "This is bounded testing, not universal safety evidence; "
        "the router exposes no execution tool.",
        "",
        "## Cost",
        "",
        f"Dedicated-key provider usage: **${accounting['provider_reported_key_usage_usd']:.8f}**. "
        f"Settled call ledger: ${settled}; unresolved conservative reservations: ${reserved}. "
        "Reservations are not billed charges. The shared application cap was $10. "
        "Pilot failures are retained, and their unknown-cost reservations were not released.",
        "",
        "## Independent review packet",
        "",
        "human-review.csv intentionally contains blank judgments. Two independent reviewers "
        "should inspect fixtures/demo/events.jsonl and the scenario protocol, record supporting "
        "source rows without reading model outputs, then adjudicate disagreement. Preserve "
        "original labels; new adjudicated labels require a versioned manifest and separate "
        "analysis. Free-form model explanations require separate claim-level human assessment.",
        "",
        "## Reproduce this analysis without API keys",
        "",
        "```sh",
        "PYTHONPATH=src uv run --frozen --no-editable python scripts/summarize_study.py \\",
        "  --study artifacts/studies/g5-20261011 --out docs/research/results",
        "```",
        "",
        "Original runs remain immutable. Later v0.2 engineering changes were not retroactively "
        "applied to these scores, and no post-hoc prompt/rule tuning is represented "
        "as held-out validation.",
    ]
    (output / "RESULTS.md").write_text("\n".join(lines) + "\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = summarize(args.study, args.out)
    print(f"Validated {result['observations']} observations; analysis saved to {args.out}")
