import json
import socket
from pathlib import Path

import pytest

from verisoc.evaluation.metrics import aggregate, ratio
from verisoc.evaluation.runner import run
from verisoc.evaluation.splits import assert_disjoint, split_families
from verisoc.evaluation.statistics import paired_bootstrap

ROOT = Path(__file__).resolve().parents[2]


def without_timing(rows):
    return [{k: v for k, v in row.items() if k != "duration_ms"} for row in rows]


def test_15_benchmark_reproducible_offline_and_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(
        socket.socket, "connect", lambda *a, **k: pytest.fail("external connection")
    )
    a = run(ROOT / "config/eval-smoke.yaml", tmp_path)
    b = run(ROOT / "config/eval-smoke.yaml", tmp_path)
    assert a != b
    for folder in (a, b):
        manifest = json.loads((folder / "manifest.json").read_text())
        assert manifest["status"] == "complete" and manifest["research_validity"] == "smoke_only"
        assert manifest["configuration"]["seed"] == 20261011
        assert len(manifest["artifact_sha256"]) == 7
        for name in (
            "predictions.jsonl",
            "claims.jsonl",
            "tool_calls_sanitized.jsonl",
            "case_metrics.jsonl",
            "summary.json",
            "metrics.csv",
            "PROVENANCE.md",
        ):
            assert (folder / name).stat().st_size > 0
    rows_a = [json.loads(r) for r in (a / "case_metrics.jsonl").read_text().splitlines()]
    rows_b = [json.loads(r) for r in (b / "case_metrics.jsonl").read_text().splitlines()]
    assert len(rows_a) == 24 * 8
    assert all(row["duration_ms"] > 0 for row in rows_a)
    assert without_timing(rows_a) == without_timing(rows_b)
    assert {r["arm"] for r in rows_a} == {
        "B0",
        "B1",
        "B2",
        "B3",
        "B3:minus-verifier",
        "B3:minus-evidence-selection",
        "B3:minus-abstention",
        "B3:minus-correlation",
    }
    for arm in ("B0", "B1", "B2", "B3"):
        ma = aggregate([r for r in rows_a if r["arm"] == arm])
        mb = aggregate([r for r in rows_b if r["arm"] == arm])
        for key in ("latency_p50_ms", "latency_p95_ms"):
            ma.pop(key)
            mb.pop(key)
        assert ma == mb
    predictions = [json.loads(r) for r in (a / "predictions.jsonl").read_text().splitlines()]
    contexts = json.dumps([r["context"] for r in predictions])
    assert (
        "gold_verdict" not in contexts
        and "expected_rule" not in contexts
        and "rationale" not in contexts
    )
    assert all(r["emitted_unsupported"] == 0 for r in rows_a if r["arm"] == "B3")
    assert any(r["emitted_unsupported"] > 0 for r in rows_a if r["arm"] == "B2")


def test_family_and_episode_leakage_rejected():
    labels = [dict(scenario_id=f"s-{i}", family=f"f-{i // 2}", episode=f"e-{i}") for i in range(12)]
    splits = split_families(labels, 123)
    assert_disjoint(labels, splits)
    broken = dict(splits)
    broken["train"] = splits["train"] + splits["test"][:1]
    with pytest.raises(ValueError, match="leakage"):
        assert_disjoint(labels, broken)
    assert ratio(0, 0) is None


def test_paired_statistics_reject_unpaired_cases():
    with pytest.raises(ValueError, match="Paired"):
        paired_bootstrap([{"scenario_id": "a", "family": "f"}], [], "recall", 1)


def test_source_and_content_fingerprints_detect_overlap():
    labels = [
        dict(scenario_id="a", family="f1", episode="e1", record_fingerprints=["shared"]),
        dict(scenario_id="b", family="f2", episode="e2", record_fingerprints=["shared"]),
    ]
    with pytest.raises(ValueError, match="content leakage"):
        assert_disjoint(labels, {"train": ["a"], "test": ["b"]})
    labels[0].pop("record_fingerprints")
    labels[1].pop("record_fingerprints")
    labels[0]["content_fingerprint"] = "identical"
    labels[1]["content_fingerprint"] = "identical"
    with pytest.raises(ValueError, match="leakage"):
        assert_disjoint(labels, {"train": ["a"], "test": ["b"]})


def test_frozen_authentication_variations_cannot_cross_partitions():
    from verisoc.evaluation.labels import load_labels
    from verisoc.evaluation.splits import attach_fingerprints

    labels = attach_fingerprints(
        load_labels(ROOT / "fixtures/demo/cases.jsonl"),
        (ROOT / "fixtures/demo/events.jsonl").read_bytes(),
    )
    split = split_families(labels, 20261011)
    partition_of = {cid: name for name, ids in split.items() for cid in ids}
    variants = [
        r
        for r in labels
        if r["scenario_type"] in ("guess_then_success", "out_of_order", "helpdesk_reset")
    ]
    assert len({partition_of[r["scenario_id"]] for r in variants}) == 1
    assert all(r["source_fingerprint"] and r["content_fingerprint"] for r in labels)


def test_replay_uses_identical_candidates_without_second_model_call(db):
    from verisoc.core.ids import demo_tenant
    from verisoc.detection.rules import detect
    from verisoc.evaluation.baseline import run_arm
    from verisoc.llm.base import Budget
    from verisoc.llm.mock import MockProvider

    class CountProvider(MockProvider):
        calls = 0

        async def generate(self, messages, budget, seed):
            self.calls += 1
            return await super().generate(messages, budget, seed)

    provider = CountProvider()
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
        b2 = run_arm(repo, case, provider, Budget(max_input_tokens=65536), "B2", "paired", 42)
        b3 = run_arm(
            repo,
            case,
            provider,
            Budget(max_input_tokens=65536),
            "B3",
            "paired",
            42,
            replay=b2.attempt,
        )
        assert provider.calls == 1
        assert b2.attempt is not b3.attempt
        assert b2.attempt.proposal == b3.attempt.proposal
        assert len(b2.emitted) > len(b3.emitted)
        assert all(d.status == "verified" for d in b3.emitted)
        with pytest.raises(ValueError, match="identical"):
            run_arm(
                repo,
                case,
                provider,
                Budget(),
                "B3",
                "paired",
                42,
                "minus-correlation",
                replay=b2.attempt,
            )


def test_hypotheses_do_not_reward_empty_reports_or_zero_recall():
    from verisoc.evaluation.statistics import hypothesis_intervals

    row = dict(
        scenario_id="a",
        family="f",
        proposal_fingerprint="same",
        gold_verdict="malicious",
        verdict="needs_review",
        emitted_factual=0,
        emitted_unsupported=0,
        citation_count=0,
        gold_citation_matches=0,
        gold_citation_count=1,
        candidate_count=1,
        candidate_unsupported=1,
        limits=[],
        duration_ms=1,
        tokens_input=1,
        tokens_output=1,
        estimated_usd=0,
    )
    result = hypothesis_intervals([row], [row], 42, replicates=100)
    assert result["H1"]["status"].startswith("inconclusive")
    assert result["H2"]["status"].startswith("inconclusive")
    assert result["independent_scientific_confirmation"] is False
    with pytest.raises(ValueError, match="unique"):
        paired_bootstrap([row, row], [row], "coverage", 42)
    with pytest.raises(ValueError, match="identical"):
        hypothesis_intervals([row], [{**row, "proposal_fingerprint": "changed"}], 42)


def test_v03_frozen_corpus_is_separate_and_annotations_reference_real_rows():
    from verisoc.core.provenance import digest
    from verisoc.evaluation.labels import load_labels
    from verisoc.evaluation.splits import attach_fingerprints

    content = (ROOT / "fixtures/v03/events.jsonl").read_bytes()
    labels = load_labels(ROOT / "fixtures/v03/cases.jsonl")
    frozen = json.loads((ROOT / "config/splits-v03.json").read_text())
    assert len(labels) == 120
    assert len({r["template"] for r in labels}) == 20
    assert len({r["family"] for r in labels}) == 6
    assert frozen["fixture_sha256"] == digest(content)
    assert_disjoint(attach_fingerprints(labels, content), frozen["splits"])
    rows = [json.loads(line) for line in content.splitlines()]
    by_id = {r["scenario_id"]: r for r in labels}
    for line in (ROOT / "fixtures/v03/expected_evidence.jsonl").read_text().splitlines():
        gold = json.loads(line)
        label = by_id[gold["scenario_id"]]
        for index in gold["supporting_rows"]:
            event = rows[index - 1]
            assert event["fixture_tenant"] == label["tenant"]
            assert label["start_at"] <= event["timestamp"] <= label["end_at"]
    old = attach_fingerprints(
        load_labels(ROOT / "fixtures/demo/cases.jsonl"),
        (ROOT / "fixtures/demo/events.jsonl").read_bytes(),
    )
    new = attach_fingerprints(labels, content)
    assert not (
        {f for r in old for f in r["record_fingerprints"]}
        & {f for r in new for f in r["record_fingerprints"]}
    )
