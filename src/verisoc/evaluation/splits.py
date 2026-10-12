import json
import random
from typing import Any

from verisoc.core.provenance import json_hash


def split_families(labels: list[dict[str, Any]], seed: int) -> dict[str, list[str]]:
    families = sorted({row["family"] for row in labels})
    random.Random(seed).shuffle(families)
    n = len(families)
    assignments = {
        f: ("train" if i < n // 2 else "dev" if i < 3 * n // 4 else "test")
        for i, f in enumerate(families)
    }
    result: dict[str, list[str]] = {"train": [], "dev": [], "test": []}
    for row in labels:
        result[assignments[row["family"]]].append(row["scenario_id"])
    assert_disjoint(labels, result)
    return {key: sorted(value) for key, value in result.items()}


def assert_disjoint(labels: list[dict[str, Any]], split: dict[str, list[str]]) -> None:
    by_id = {row["scenario_id"]: row for row in labels}
    owners: dict[tuple[str, str], str] = {}
    for partition, ids in split.items():
        for case_id in ids:
            row = by_id[case_id]
            for fingerprint in row.get("record_fingerprints", []):
                key = ("source_record", fingerprint)
                if key in owners and owners[key] != partition:
                    raise ValueError("Partition content leakage")
                owners[key] = partition
            for field in (
                "scenario_id",
                "family",
                "episode",
                "source_fingerprint",
                "content_fingerprint",
            ):
                if field not in row:
                    continue
                key = (field, row[field])
                if key in owners and owners[key] != partition:
                    raise ValueError("Partition leakage")
                owners[key] = partition
    if set(by_id) != {i for ids in split.values() for i in ids}:
        raise ValueError("Incomplete split")


def attach_fingerprints(labels: list[dict[str, Any]], content: bytes) -> list[dict[str, Any]]:
    rows = [json.loads(line) for line in content.splitlines()]
    result = []
    for label in labels:
        episode = [
            (i + 1, row)
            for i, row in enumerate(rows)
            if row.get("fixture_tenant") == label["tenant"]
            and label["start_at"] <= row["timestamp"] <= label["end_at"]
        ]
        if not episode:
            raise ValueError("Empty source episode")
        fingerprints = [
            json_hash({k: v for k, v in row.items() if k != "fixture_tenant"}) for _, row in episode
        ]
        result.append(
            dict(
                label,
                source_fingerprint=json_hash([i for i, _ in episode]),
                content_fingerprint=json_hash(sorted(fingerprints)),
                record_fingerprints=sorted(set(fingerprints)),
            )
        )
    return result
