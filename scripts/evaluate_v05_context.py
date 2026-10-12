"""Paired new development controls; immutable output and no hosted providers."""

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.evaluation.v05_oracle import ContextOracle
from verisoc.evaluation.v05_statistics import fpr_upper
from verisoc.evidence.registry import EvidenceRegistry
from verisoc.ingest.importer import import_jsonl
from verisoc.investigation.evidence_pipeline import CaseWindow, open_window
from verisoc.storage.repository import Database
from verisoc.v05.context_models import ContextAuthority, ContextBundle
from verisoc.v05.triage import triage

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    folder = ROOT / "fixtures/v05-dev"
    content = (folder / "events.jsonl").read_bytes()
    labels = [json.loads(line) for line in (folder / "cases.jsonl").read_text().splitlines()]
    oracle = ContextOracle(content, "v05-dev")
    rows = []
    reports = []
    checked = 0
    unsupported = 0
    db = Database("sqlite:///:memory:")
    try:
        for tenant in sorted({r["tenant"] for r in labels}):
            with db.scope(demo_tenant(tenant)) as repo:
                import_jsonl(repo, content, "v05-dev", fixture_tenant=tenant)
                context = (folder / f"context-{tenant}.jsonl").read_bytes()
                bundle = ContextBundle(
                    content=context,
                    authority=ContextAuthority(
                        tenant_id=repo.tenant,
                        dataset_id="v05-dev",
                        source_id="synthetic-context-custodian",
                        file_sha256=digest(context),
                        authorization_reference="new-author-defined-controls-not-human-signoff",
                    ),
                )
                for label in (r for r in labels if r["tenant"] == tenant):
                    case = open_window(
                        repo,
                        CaseWindow.model_validate(
                            dict(
                                dataset_id="v05-dev",
                                start_at=label["start_at"],
                                end_at=label["end_at"],
                            )
                        ),
                    )
                    registry = EvidenceRegistry(repo, case)
                    start = time.perf_counter()
                    baseline = triage(repo, case)
                    corrected = triage(repo, case, (bundle,))
                    duration = (time.perf_counter() - start) * 1000
                    assert baseline.indicator_evidence == corrected.indicator_evidence
                    for fact in registry.facts.values():
                        checked += 1
                        unsupported += not oracle.supports_fact(case, fact)
                    for fact in corrected.verified_context:
                        checked += 1
                        unsupported += not oracle.supports_context(
                            case, registry.facts[fact.explained_fact_id], fact, bundle
                        )
                    rows.append(
                        dict(
                            scenario_id=label["scenario_id"],
                            family=label["family"],
                            template=label["template"],
                            gold_verdict=label["verdict"],
                            baseline_flag=baseline.triage_flag,
                            context_flag=corrected.triage_flag,
                            baseline_incident_verdict=baseline.incident_verdict,
                            context_incident_verdict=corrected.incident_verdict,
                            disposition=corrected.disposition,
                            reasons=corrected.reason_codes,
                            observation_count=len(registry.facts),
                            context_count=len(corrected.verified_context),
                            duration_ms=duration,
                        )
                    )
                    reports.append(
                        dict(
                            scenario_id=label["scenario_id"],
                            report=corrected.model_dump(mode="json"),
                        )
                    )
    finally:
        db.engine.dispose()
    metrics = {}
    for arm in ("baseline", "context"):
        benign = [r for r in rows if r["gold_verdict"] == "benign"]
        positive = [r for r in rows if r["gold_verdict"] == "malicious"]
        fp = sum(r[arm + "_flag"] for r in benign)
        metrics[arm] = dict(
            benign_false_positives=fp,
            benign_denominator=len(benign),
            benign_fpr=fp / len(benign),
            one_sided_binomial_upper_95=fpr_upper(fp, len(benign)),
            true_positive_flags=sum(r[arm + "_flag"] for r in positive),
            positive_denominator=len(positive),
            total_flags=sum(r[arm + "_flag"] for r in rows),
            total_cases=len(rows),
            incident_verdict_coverage=0,
            uncertainty_scope="synthetic controls; independence required for binomial inference",
        )
    summary = dict(
        validity="smoke_only_new_author_defined_development_controls",
        paired_cases=len(rows),
        independent_families=0,
        metrics=metrics,
        raw_oracle_checked=checked,
        raw_oracle_unsupported=unsupported,
        old_4_of_16_result="unchanged; required context absent",
        zero_of_16_one_sided_upper_95=fpr_upper(0, 16),
        research_fpr_gate="BLOCKED",
        H2="BLOCKED",
        provider_calls=0,
        new_cost_usd=0,
    )
    for name, data in [("summary.json", summary), ("rows.json", rows), ("reports.json", reports)]:
        (args.out / name).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    inputs = [*folder.glob("*"), *ROOT.glob("src/**/*.py"), Path(__file__)]
    manifest = dict(
        git_sha=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        dirty=bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)),
        input_sha256={
            str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs if p.is_file()
        },
        output_sha256={
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in args.out.iterdir()
        },
        validity="smoke_only",
        new_provider_cost_usd=0,
    )
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2))
    if unsupported:
        raise SystemExit("Independent raw oracle disagreement")


if __name__ == "__main__":
    main()
