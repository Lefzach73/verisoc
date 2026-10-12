import csv
import importlib.metadata
import json
import platform
import subprocess
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import uuid4

import yaml
from pydantic import Field

from verisoc.core.ids import demo_tenant, stable_id
from verisoc.core.models import Case, Frozen
from verisoc.core.provenance import digest, json_hash
from verisoc.detection.rules import RULE_VERSION, detect
from verisoc.evaluation.baseline import ABLATIONS, ARMS, run_arm
from verisoc.evaluation.labels import load_labels
from verisoc.evaluation.metrics import aggregate
from verisoc.evaluation.oracle import RawRecordOracle
from verisoc.evaluation.splits import assert_disjoint, attach_fingerprints, split_families
from verisoc.evaluation.statistics import paired_bootstrap
from verisoc.ingest.importer import import_jsonl
from verisoc.investigation.pipeline import Attempt
from verisoc.investigation.prompts import PROMPT_VERSION
from verisoc.llm.base import Budget, Provider
from verisoc.llm.ledger import SpendLedger
from verisoc.llm.mock import MockProvider
from verisoc.llm.openai_compatible import OpenAICompatibleProvider
from verisoc.storage.repository import DEMO_MODE, Database
from verisoc.verification.verifier import VERIFIER_VERSION


class AdapterConfig(Frozen):
    endpoint: str
    model: str
    allow_network: bool = False
    allow_hosted: bool = False
    input_usd_per_million: float | None = None
    output_usd_per_million: float | None = None
    price_snapshot: str = ""
    routing_provider: str | None = None
    reasoning_enabled: bool | None = None
    # Secret is supplied in VERISOC_MODEL_API_KEY, never YAML/manifest.


class EvaluationConfig(Frozen):
    schema_version: Literal["1.0"]
    seed: int
    fixture: str
    labels: str
    evidence: str
    arms: tuple[str, ...] = ("B0", "B1", "B2", "B3")
    ablations: tuple[str, ...] = ()
    partition: Literal["all", "train", "dev", "test"] = "all"
    budget: Budget = Field(default_factory=Budget)
    adapter: AdapterConfig | None = None
    split_manifest: str | None = None
    split_strategy: Literal["seeded", "frozen"] = "seeded"
    spend_ledger: str | None = None
    study_cap_usd: Annotated[float, Field(gt=0, le=100)] | None = None
    scenario_ids: tuple[str, ...] | None = None
    paired_proposals: bool = False
    ablation_scenario_ids: tuple[str, ...] | None = None
    bootstrap_replicates: Annotated[int, Field(ge=100, le=10000)] = 2000


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


def append_json(path: Path, value: Any) -> None:
    with path.open("a") as handle:
        handle.write(json.dumps(value, sort_keys=True, allow_nan=False) + "\n")


def git_state(root: Path) -> dict[str, Any]:
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True
    )
    return {
        "sha": sha.stdout.strip() if sha.returncode == 0 else None,
        "dirty": bool(status.stdout) if status.returncode == 0 else None,
    }


def build_provider(config: EvaluationConfig, root: Path, provider_name: str) -> Provider:
    import os

    provider: Provider
    if provider_name == "mock":
        provider = MockProvider()
    elif provider_name in ("openai-compatible", "openrouter") and config.adapter:
        provider = OpenAICompatibleProvider(
            **config.adapter.model_dump(),
            api_key=os.getenv("VERISOC_MODEL_API_KEY"),
            ledger=SpendLedger(root / config.spend_ledger, config.study_cap_usd)
            if config.spend_ledger and config.study_cap_usd
            else None,
        )
    else:
        raise ValueError("Provider unavailable or opt-in config absent")
    if provider_name == "openrouter" and provider.provider_id != "openrouter":
        raise ValueError("OpenRouter selector requires the OpenRouter endpoint")
    return provider


def run(config_path: Path, out: Path, provider_name: str = "mock") -> Path:

    root = config_path.resolve().parents[1]
    config = EvaluationConfig.model_validate(yaml.safe_load(config_path.read_text()))
    if not set(config.arms).issubset(ARMS) or not set(config.ablations).issubset(ABLATIONS):
        raise ValueError("Invalid arms/ablations")
    if len(set(config.arms)) != len(config.arms):
        raise ValueError("Duplicate arms")
    if config.paired_proposals and (
        "B2" not in config.arms
        or "B3" not in config.arms
        or config.arms.index("B2") > config.arms.index("B3")
    ):
        raise ValueError("Paired proposals require B2 before B3")
    provider = build_provider(config, root, provider_name)
    content = (root / config.fixture).read_bytes()
    oracle = RawRecordOracle(content)
    labels = attach_fingerprints(load_labels(root / config.labels), content)
    gold_rows = {
        r["scenario_id"]: r["supporting_rows"]
        for r in (json.loads(line) for line in (root / config.evidence).read_text().splitlines())
    }
    splits = split_families(labels, config.seed)
    if config.split_manifest:
        frozen = json.loads((root / config.split_manifest).read_text())
        if config.split_strategy == "frozen":
            splits = frozen["splits"]
            if set(splits) != {"train", "dev", "test"}:
                raise ValueError("Invalid frozen partitions")
            assert_disjoint(labels, splits)
        if (
            frozen["fixture_sha256"] != digest(content)
            or frozen["labels_sha256"] != digest((root / config.labels).read_bytes())
            or frozen["seed"] != config.seed
            or frozen["splits"] != splits
        ):
            raise ValueError("Frozen split manifest mismatch; no silent retuning")

    selected = (
        labels
        if config.partition == "all"
        else [r for r in labels if r["scenario_id"] in splits[config.partition]]
    )
    if config.scenario_ids is not None:
        if not set(config.scenario_ids).issubset({r["scenario_id"] for r in selected}):
            raise ValueError("Unknown or out-of-partition scenario")
        selected = [row for row in selected if row["scenario_id"] in config.scenario_ids]
    if not selected:
        raise ValueError("Empty evaluation partition")
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:12]
    destination = out / run_id
    destination.mkdir(parents=True, exist_ok=False)
    # Create-exclusive artifact paths: unique runs never overwrite previous predictions.
    for name in (
        "predictions.jsonl",
        "claims.jsonl",
        "tool_calls_sanitized.jsonl",
        "case_metrics.jsonl",
    ):
        (destination / name).touch(exist_ok=False)
    validity = (
        "smoke_only" if provider_name == "mock" else "synthetic_model_run_not_independent_study"
    )
    versions = {
        d.metadata["Name"]: d.version
        for d in importlib.metadata.distributions()
        if d.metadata["Name"]
    }
    manifest = {
        "run_id": run_id,
        "status": "running",
        "timestamp": datetime.now(UTC).isoformat(),
        "research_validity": validity,
        "git": git_state(root),
        "host_type": platform.system(),
        "python": platform.python_version(),
        "dependency_lock_sha256": digest((root / "uv.lock").read_bytes()),
        "dependencies": versions,
        "dataset_id": "demo",
        "dataset_sha256": digest(content),
        "dataset_license": "MIT-original-synthetic",
        "labels_sha256": digest((root / config.labels).read_bytes()),
        "evidence_annotations_sha256": digest((root / config.evidence).read_bytes()),
        "case_ids_sha256": json_hash(sorted(r["scenario_id"] for r in selected)),
        "split_seed": config.seed,
        "splits": splits,
        "source_fingerprints": {
            r["scenario_id"]: {
                k: r[k]
                for k in ("source_fingerprint", "content_fingerprint", "record_fingerprints")
            }
            for r in labels
        },
        "source_code_sha256": {
            str(p.relative_to(root)): digest(p.read_bytes())
            for p in sorted((root / "src").rglob("*.py"))
        },
        "provider": provider.provider_id,
        "model": provider.model_id,
        "model_parameters": {"seed": config.seed, "temperature": 0},
        "prompt_version": PROMPT_VERSION,
        "verifier_version": VERIFIER_VERSION,
        "rule_version": RULE_VERSION,
        "rls_mode": DEMO_MODE,
        "price_snapshot": provider.price_snapshot,
        "price_input_usd_per_million": provider.input_usd_per_million,
        "price_output_usd_per_million": provider.output_usd_per_million,
        "configuration": config.model_dump(mode="json"),
        "annotation": "author_specified_not_independently_reviewed",
        "failure_cost_note": "Provider failures may incur unreported billing; "
        "metered usage only is summed.",
    }
    write_json(destination / "manifest.json", manifest)
    metrics: list[dict[str, Any]] = []
    db = Database("sqlite:///:memory:")
    try:
        for tenant in sorted({row["tenant"] for row in selected}):
            with db.scope(demo_tenant(tenant)) as repo:
                import_jsonl(repo, content, "demo", fixture_tenant=tenant)
                correlation_cases = detect(repo, "demo")
                events = repo.list_events("demo")
                for label in (row for row in selected if row["tenant"] == tenant):
                    # Evaluation windows carry no verdict/family/rationale into runtime cases.
                    scoped = [
                        e
                        for e in events
                        if label["start_at"] <= e.occurred_at.isoformat() <= label["end_at"]
                    ]
                    if not scoped:
                        raise ValueError("Annotation has no events")
                    annotations = set(gold_rows[label["scenario_id"]])
                    gold_ids = {
                        str(e.event_id) for e in scoped if e.source_ref.row_index in annotations
                    }
                    use_ablations = (
                        config.ablation_scenario_ids is None
                        or label["scenario_id"] in config.ablation_scenario_ids
                    )
                    variants = (
                        [(arm, None) for arm in config.arms] + [("B3", a) for a in config.ablations]
                        if use_ablations
                        else [(arm, None) for arm in config.arms]
                    )
                    shared_attempt: Attempt | None = None
                    for arm, ablation in variants:
                        alerts = [
                            c.alert
                            for c in correlation_cases
                            if c.start_at >= scoped[0].occurred_at
                            and c.end_at <= scoped[-1].occurred_at
                            and c.alert is not None
                        ]
                        if ablation == "minus-correlation":
                            alerts = [
                                a for a in alerts if a.rule_id != "auth_success_after_failures"
                            ]
                        alert = (
                            max(alerts, key=lambda a: (a.severity == "high", a.rule_id))
                            if alerts
                            else None
                        )
                        case = Case(
                            case_id=stable_id(
                                repo.tenant,
                                "demo",
                                *sorted(str(e.event_id) for e in scoped),
                                ablation == "minus-correlation",
                            ),
                            tenant_id=repo.tenant,
                            dataset_id="demo",
                            event_ids=tuple(e.event_id for e in scoped),
                            start_at=scoped[0].occurred_at,
                            end_at=scoped[-1].occurred_at,
                            alert=alert,
                        )
                        repo.put_case(case)
                        name = arm + (":" + ablation if ablation else "")
                        replay = (
                            shared_attempt
                            if config.paired_proposals
                            and arm == "B3"
                            and ablation in (None, "minus-verifier", "minus-abstention")
                            else None
                        )
                        prediction = run_arm(
                            repo,
                            case,
                            provider,
                            config.budget,
                            arm,
                            run_id,
                            config.seed,
                            ablation,
                            replay=replay,
                        )
                        if arm == "B2" and config.paired_proposals:
                            shared_attempt = prediction.attempt
                        emitted = tuple(
                            d
                            for d in prediction.emitted
                            if d.candidate.claim_kind != "analyst_inference"
                        )
                        citations = {str(e) for d in emitted for e in d.candidate.subject_event_ids}
                        row = {
                            "scenario_id": label["scenario_id"],
                            "family": label["family"],
                            "tenant": tenant,
                            "noise": label["noise"],
                            "injection": label["injection"],
                            "volume": label["volume"],
                            "partition": next(
                                p for p, ids in splits.items() if label["scenario_id"] in ids
                            ),
                            "arm": name,
                            "gold_verdict": label["verdict"],
                            "verdict": prediction.verdict,
                            "candidate_count": len(prediction.decisions),
                            "candidate_unsupported": sum(
                                not oracle.supports(case, d.candidate) for d in prediction.decisions
                            ),
                            "emitted_factual": len(emitted),
                            "emitted_unsupported": sum(
                                not oracle.supports(case, d.candidate) for d in emitted
                            ),
                            "citation_count": len(citations),
                            "gold_citation_count": len(gold_ids),
                            "gold_citation_matches": len(citations.intersection(gold_ids)),
                            "limits": list(prediction.attempt.limits),
                            "duration_ms": prediction.attempt.duration_ms,
                            "tokens_input": prediction.attempt.tokens_input,
                            "tokens_output": prediction.attempt.tokens_output,
                            "estimated_usd": prediction.attempt.estimated_usd,
                            "new_provider_cost_usd": 0
                            if replay
                            else prediction.attempt.estimated_usd,
                            "reused_proposal": replay is not None,
                            "proposal_fingerprint": json_hash(
                                prediction.attempt.proposal.model_dump(mode="json")
                            ),
                            "error": prediction.verdict != label["verdict"],
                        }
                        metrics.append(row)
                        append_json(destination / "case_metrics.jsonl", row)
                        append_json(
                            destination / "predictions.jsonl",
                            {
                                "scenario_id": label["scenario_id"],
                                "arm": name,
                                "case_id": str(case.case_id),
                                "verdict": prediction.verdict,
                                "gated": prediction.gated,
                                "candidate": prediction.attempt.proposal.model_dump(mode="json"),
                                "raw_outputs": prediction.attempt.raw_outputs,
                                "provider_calls": prediction.attempt.provider_calls,
                                "context": prediction.attempt.context,
                                "reused_proposal": replay is not None,
                                "vetted_report": prediction.report.model_dump(mode="json")
                                if prediction.report
                                else None,
                            },
                        )
                        for decision in prediction.decisions:
                            append_json(
                                destination / "claims.jsonl",
                                {
                                    "scenario_id": label["scenario_id"],
                                    "arm": name,
                                    "decision": decision.model_dump(mode="json"),
                                    "raw_oracle_support": oracle.supports(case, decision.candidate),
                                },
                            )
                        for call in prediction.attempt.tool_trace:
                            append_json(
                                destination / "tool_calls_sanitized.jsonl",
                                {"scenario_id": label["scenario_id"], "arm": name, **call},
                            )
        by_arm: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in metrics:
            by_arm[row["arm"]].append(row)
        summary = {
            "research_validity": validity,
            "claim_scoring": "Independent raw-record oracle; human narrative annotation pending",
            "arms": {a: aggregate(rows) for a, rows in by_arm.items()},
            "h1_h2": "NOT_CONFIRMED: author-labeled synthetic results require independent review",
            "security_outcomes": "See invariant/RLS tests; no inferred model leakage rate",
            "errors": [
                {
                    "scenario_id": r["scenario_id"],
                    "arm": r["arm"],
                    "gold": r["gold_verdict"],
                    "predicted": r["verdict"],
                    "limits": r["limits"],
                }
                for r in metrics
                if r["error"]
            ],
        }
        strata = {}
        for field in ("gold_verdict", "noise", "injection", "volume", "tenant", "partition"):
            strata[field] = {
                str(value): {
                    a: aggregate([r for r in rows if r[field] == value])
                    for a, rows in by_arm.items()
                }
                for value in sorted({r[field] for r in metrics}, key=str)
            }
        summary["strata"] = strata
        if "B3" in by_arm and "B2" in by_arm:
            summary["paired_ci"] = [
                paired_bootstrap(
                    by_arm["B3"], by_arm["B2"], m, config.seed, config.bootstrap_replicates
                )
                for m in ("unsupported_factual_claim_rate", "recall", "coverage")
            ]
        write_json(destination / "summary.json", summary)
        with (destination / "metrics.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(metrics[0]))
            writer.writeheader()
            writer.writerows(metrics)
        (destination / "PROVENANCE.md").write_text(
            "Original synthetic engineering fixtures. No external data.\n"
            "Author-specified gold; no independent review. Mock byte counts are smoke metering.\n"
            "Comparator claims never served through the vetted API. All failures retained.\n"
        )
        if isinstance(provider, OpenAICompatibleProvider) and provider.ledger:
            snapshot = provider.ledger.snapshot()
            manifest["study_spend"] = {k: v for k, v in snapshot.items() if k != "requests"}
        manifest["status"] = "complete"
        manifest["artifact_sha256"] = {
            p.name: digest(p.read_bytes())
            for p in destination.iterdir()
            if p.name != "manifest.json"
        }
        write_json(destination / "manifest.json", manifest)
        return destination
    except BaseException:
        manifest["status"] = "failed"
        write_json(destination / "manifest.json", manifest)
        raise
    finally:
        db.engine.dispose()
