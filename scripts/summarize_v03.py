"""Verify and analyze the frozen v0.3 study offline, retaining all failed cases."""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

from verisoc.evaluation.metrics import aggregate
from verisoc.evaluation.statistics import hypothesis_intervals, paired_bootstrap

FROZEN_COMMIT = "2746044b58ee9c059d7d669c8d7d9d124dca9684"
MODELS = ("openai/gpt-4.1-mini", "google/gemini-2.5-flash")
MAIN = ("B0", "B1", "B2", "B3")
ABLATIONS = ("minus-verifier", "minus-evidence-selection", "minus-abstention", "minus-correlation")


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def validate_run(path):
    manifest = json.loads((path / "manifest.json").read_text())
    if manifest["git"] != {"sha": FROZEN_COMMIT, "dirty": False}:
        raise ValueError("Unexpected study source provenance")
    if manifest["model"] not in MODELS:
        raise ValueError("Unexpected study model")
    if manifest.get("status", "complete") != "complete":
        raise ValueError("Study is incomplete; do not omit unfinished cases")
    if not manifest.get("artifact_sha256"):
        raise ValueError("Missing artifact inventory")
    for name, expected in manifest["artifact_sha256"].items():
        if (
            Path(name).name != name
            or hashlib.sha256((path / name).read_bytes()).hexdigest() != expected
        ):
            raise ValueError("Artifact checksum mismatch")
    return manifest


def percent(value):
    return "undefined" if value is None else f"{100 * value:.1f}%"


def charts(models, output):
    import matplotlib

    matplotlib.use("Agg")
    matplotlib.rcParams["svg.hashsalt"] = "verisoc-v03-20261012"
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter

    colors = ["#6b7280", "#d97706", "#b45353", "#087f8c"]
    fig, axes = plt.subplots(2, 3, figsize=(12, 6), layout="constrained")
    for row, model in enumerate(MODELS):
        for col, (metric, title) in enumerate(
            (
                ("recall", "Incident recall"),
                ("coverage", "Verdict coverage"),
                ("unsupported_factual_claim_rate", "Unsupported typed-claim rate"),
            )
        ):
            ax = axes[row, col]
            values = [models[model]["arms"][a][metric] for a in MAIN]
            bars = ax.bar(MAIN, [v or 0 for v in values], color=colors, width=0.6)
            ax.set_ylim(0, 1.15)
            ax.yaxis.set_major_formatter(PercentFormatter(1))
            ax.set_title(f"{model.split('/')[-1]} · {title}", fontsize=10)
            ax.spines[["top", "right"]].set_visible(False)
            ax.bar_label(bars, labels=[percent(v) for v in values], padding=3, fontsize=9)
    fig.suptitle(
        "120 procedural cases per model · point estimates, all failures retained", fontsize=12
    )
    fig.savefig(output / "quality.png", dpi=160)
    fig.savefig(output / "quality.svg", metadata={"Date": None})
    plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), layout="constrained")
    for ax, model in zip(axes, MODELS, strict=True):
        values = [100 * models[model]["arms"][a]["estimated_usd"] / 120 for a in MAIN]
        bars = ax.bar(MAIN, values, color=colors, width=0.6)
        ax.bar_label(bars, fmt="%.3f", padding=3, fontsize=9)
        ax.set_title(model.split("/")[-1])
        ax.set_ylabel("Standalone pipeline cost, US cents/case")
        ax.spines[["top", "right"]].set_visible(False)
        ax.set_ylim(0, max(values) * 1.25 if max(values) else 1)
    fig.suptitle("B3 reuses the B2 generation; actual billing is counted once", fontsize=11)
    fig.savefig(output / "cost.png", dpi=160)
    fig.savefig(output / "cost.svg", metadata={"Date": None})
    plt.close(fig)
    for path in output.glob("*.svg"):
        path.write_text("\n".join(line.rstrip() for line in path.read_text().splitlines()) + "\n")


def summarize(study, output):
    all_rows, all_claims, runs = [], [], []
    predictions = {}
    expected = {
        (model, f"v03-{i:03d}", arm) for model in MODELS for i in range(1, 121) for arm in MAIN
    }
    expected |= {
        (model, f"v03-{i:03d}", "B3:" + arm)
        for model in MODELS
        for i in range(1, 121)
        if (i - 1) % 6 in (0, 3)
        for arm in ABLATIONS
    }
    seen = set()
    for directory in sorted(p for p in study.iterdir() if p.is_dir()):
        manifest = validate_run(directory)
        model = manifest["model"]
        local = records(directory / "case_metrics.jsonl")
        for row in local:
            key = (model, row["scenario_id"], row["arm"])
            if key in seen:
                raise ValueError("Duplicate case/arm/model observation")
            seen.add(key)
            all_rows.append({**row, "model": model, "run_id": directory.name})
        for row in records(directory / "predictions.jsonl"):
            predictions[(model, row["scenario_id"], row["arm"])] = row
        all_claims.extend({**r, "model": model} for r in records(directory / "claims.jsonl"))
        runs.append(
            {
                "run_id": directory.name,
                "manifest_sha256": hashlib.sha256(
                    (directory / "manifest.json").read_bytes()
                ).hexdigest(),
            }
        )
    if seen != expected or set(predictions) != expected or len(runs) != 8:
        raise ValueError("Expected exactly eight complete shards and 1,280 observations")
    for model in MODELS:
        for i in range(1, 121):
            left = predictions[(model, f"v03-{i:03d}", "B2")]
            right = predictions[(model, f"v03-{i:03d}", "B3")]
            if any(
                left[field] != right[field]
                for field in ("candidate", "context", "raw_outputs", "provider_calls")
            ):
                raise ValueError("B2/B3 generation or evidence opportunity differs")
    models = {}
    for model in MODELS:
        rows = [r for r in all_rows if r["model"] == model]
        by_arm = {
            arm: [r for r in rows if r["arm"] == arm] for arm in sorted({r["arm"] for r in rows})
        }
        reasons = defaultdict(Counter)
        distinct = defaultdict(dict)
        for claim in (c for c in all_claims if c["model"] == model):
            decision = claim["decision"]
            reasons[claim["arm"]].update([decision["reason_code"]])
            candidate = decision["candidate"]
            if candidate["claim_kind"] == "analyst_inference":
                continue
            if (
                claim["arm"].startswith("B3")
                and claim["arm"] != "B3:minus-verifier"
                and decision["status"] != "verified"
            ):
                continue
            subjects = candidate["subject_event_ids"]
            if candidate["claim_kind"] in ("shared_host", "shared_user"):
                subjects = sorted(subjects)
            key = json.dumps(
                [
                    claim["scenario_id"],
                    candidate["claim_kind"],
                    subjects,
                    {k: v for k, v in candidate["parameters"].items() if v is not None},
                ],
                sort_keys=True,
            )
            distinct[claim["arm"]][key] = claim["raw_oracle_support"]
        ablations = {}
        for ablation in ABLATIONS:
            variant = by_arm["B3:" + ablation]
            ids = {r["scenario_id"] for r in variant}
            matched = [r for r in by_arm["B3"] if r["scenario_id"] in ids]
            ablations[ablation] = {
                "matched_cases": len(ids),
                "B3": aggregate(matched),
                "variant": aggregate(variant),
                "B3_minus_variant": [
                    paired_bootstrap(matched, variant, metric, 20261012, 2000)
                    for metric in ("recall", "coverage", "unsupported_factual_claim_rate")
                ],
            }
        models[model] = {
            "arms": {arm: aggregate(items) for arm, items in by_arm.items()},
            "hypotheses": hypothesis_intervals(by_arm["B3"], by_arm["B2"], 20261012),
            "ablations": ablations,
            "predicate_reasons": {k: dict(v) for k, v in reasons.items()},
            "distinct_factual_claims": {
                arm: {"emitted": len(values), "unsupported": sum(not v for v in values.values())}
                for arm, values in distinct.items()
            },
            "strata": {
                field: {
                    str(value): {
                        arm: aggregate([r for r in items if r[field] == value])
                        for arm, items in by_arm.items()
                    }
                    for value in sorted({r[field] for r in rows}, key=str)
                }
                for field in ("family", "gold_verdict", "noise", "volume", "injection", "tenant")
            },
            "failure_limits": dict(Counter(limit for row in rows for limit in row["limits"])),
        }
    robust = {}
    for directory in sorted((study.parent / "v03-robustness").iterdir()):
        if directory.is_dir():
            manifest = validate_run(directory)
            if manifest["model"] in robust:
                raise ValueError("Duplicate robustness model")
            robust[manifest["model"]] = json.loads((directory / "summary.json").read_text())
    if set(robust) != set(MODELS) or any(r["cases"] != 5 for r in robust.values()):
        raise ValueError("Robustness evaluation incomplete")
    ledger = json.loads((study.parent / "v03-full-ledger.json").read_text())
    settled = sum((Decimal(r.get("charged_usd", "0")) for r in ledger["requests"]), Decimal(0))
    reserved = sum(
        (Decimal(r["reserved_usd"]) for r in ledger["requests"] if r["state"] != "settled"),
        Decimal(0),
    )
    billed = sum(r["new_provider_cost_usd"] for r in all_rows)
    summary = {
        "study_source": FROZEN_COMMIT,
        "observations": len(all_rows),
        "runs": runs,
        "research_validity": (
            "prospective_procedural_time_environment_shift_not_independent_human_study"
        ),
        "models": models,
        "robustness": robust,
        "accounting": {
            "full_study_incremental_usd": billed,
            "cumulative_settled_usd": str(settled),
            "unknown_or_pending_reservations_usd": str(reserved),
            "cap_usd": ledger["cap_usd"],
            "ledger_states": dict(Counter(r["state"] for r in ledger["requests"])),
        },
        "independent_scientific_confirmation": False,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    with (output / "metrics.csv").open("w") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(all_rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(all_rows)
    with (output / "errors.jsonl").open("w") as handle:
        for row in all_rows:
            if row["error"] or row["limits"]:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    with (output / "human-review.csv").open("w") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            [
                "scenario_id",
                "reviewer_1_verdict",
                "reviewer_2_verdict",
                "adjudicated_verdict",
                "supporting_source_rows",
                "rationale",
            ]
        )
        writer.writerows([[f"v03-{i:03d}"] + [""] * 5 for i in range(1, 121)])
    charts(models, output)
    lines = [
        "# v0.3 controlled evaluation results",
        "",
        "This is a completed internal evaluation on procedural synthetic cases. It is not "
        "independent scientific validation, a universal safety proof or evidence of real-world "
        "compromise detection.",
        "",
        f"Frozen source `{FROZEN_COMMIT}`. Eight complete shards, all artifact checksums "
        "validated, 120 cases/model, 1,280 total arm/model observations and ten inert adversarial "
        "cases. Every B2/B3 pair uses identical candidate, context, raw outputs and provider "
        "completion metadata. Failures remain in every denominator.",
        "",
        "## Main arms",
        "",
        "| Model | Arm | Recall | Precision | Verdict coverage | Observation coverage | "
        "Unsupported typed claims | Failed/limited |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for model in MODELS:
        for arm in MAIN:
            m = models[model]["arms"][arm]
            lines.append(
                f"| {model.split('/')[-1]} | {arm} | {percent(m['recall'])} | "
                f"{percent(m['precision'])} | {percent(m['coverage'])} | "
                f"{percent(m['observation_coverage'])} | "
                f"{m['emitted_unsupported_claims']}/{m['emitted_factual_claims']} | "
                f"{m['malformed_or_failed_cases']}/120 |"
            )
    lines += [
        "",
        "![Quality point estimates](quality.png)",
        "",
        "Observation coverage means at least one emitted factual predicate, not a resolved "
        "incident or a correct verdict. Intent is stipulated in the scenario, with deliberate "
        "benign/malicious lookalikes. Precision and false positives must be read alongside recall.",
        "",
        "## Predeclared hypothesis tests",
        "",
    ]
    for model in MODELS:
        h = models[model]["hypotheses"]
        lines += [
            f"- **{model}**: H1 typed-support proxy `{h['H1']['status']}`, "
            f"contrast 95% interval `{h['H1']['ci95']}`; H2 procedural recall "
            f"`{h['H2']['status']}`, difference 95% interval `{h['H2']['ci95']}`."
        ]
    lines += [
        "",
        "H1 requires at least halving unsupported emitted typed claims; H2 uses a 5-point "
        "recall noninferiority margin. An error-free comparator or empty output cannot establish "
        "H1. Zero baseline recall or B3 verdict coverage cannot establish useful H2. Intervals use "
        "2,000 paired bootstrap draws over only six mechanism families; they are fragile. "
        "Full denominators, valid draws, unique-assertion counts and error strata "
        "are in summary.json.",
        "",
        "These are bounded support-proxy and procedural-label outcomes. Independent human "
        "narrative/intent judgments and a separately labeled external efficacy study remain "
        "missing. Do not call all scientific hypotheses proven.",
        "",
        "## Failure analysis",
        "",
        "GPT B2/B3 recorded ten limited cases (four tool-budget failures, four provider failures, "
        "one truncation and one invalid candidate/tool). Gemini B2/B3 recorded 92 limited cases "
        "(77 truncated responses, 13 provider failures and two invalid candidates/tools). "
        "The later output-quota repair is a separate engineering regression. These scientific "
        "results still describe the original frozen source and retain every failure.",
        "",
        "## Ablations and costs",
        "",
        "All four ablations use the same prospectively selected 40-case subset, including two "
        "variants of every template. Compare their paired B3 subset, not the full 120-case "
        "aggregate. Exact input changes and matched intervals are in summary.json.",
        "",
        "![Standalone pipeline costs](cost.png)",
        "",
        f"New provider charges represented by this full study: **${billed:.8f}**. "
        f"Cumulative settled journal, including earlier pilots/studies: **${settled}**. "
        f"Unsettled conservative reservations: ${reserved}; "
        f"total application cap ${ledger['cap_usd']}. "
        "Replayed candidates are counted once in incremental billing. Per-arm standalone cost "
        "includes the generation that would be required to run that arm alone.",
        "",
        "## Robustness and independent checks",
        "",
    ]
    for model in MODELS:
        r = robust[model]
        lines.append(
            f"- {model}: {r['cases']} inert cases, {r['exposures']} observed foreign exposures, "
            f"{r['unauthorized_actions']} unauthorized actions, "
            f"{r['unsupported_verified']} unsupported verified outputs, "
            f"{r['failures']} failed/limited."
        )
    lines += [
        "",
        "The separate finite predicate/oracle audit and external EVTX format audit are in "
        "the parent directory. External records were not treated as independently adjudicated "
        "case labels. The raw external corpus and all credentials are excluded from GitHub.",
        "",
        "## Reproduce without model calls",
        "",
        "```sh",
        "PYTHONPATH=src uv run --frozen --no-editable --extra analysis "
        "python scripts/summarize_v03.py \\",
        "  --study artifacts/studies/v03-full --out docs/research/v03/results",
        "```",
        "",
        "Raw synthetic artifacts are supplied in the local release archive. Human-review.csv "
        "contains blank judgments for an actual two-reviewer adjudication process. No human "
        "reviews, publication acceptance or independent novelty claims have been fabricated.",
    ]
    (output / "RESULTS.md").write_text("\n".join(lines) + "\n")
    print(f"Validated {len(all_rows)} observations; report saved to {output}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summarize(args.study, args.out)
