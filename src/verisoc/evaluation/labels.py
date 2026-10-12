"""Evaluation-only annotation access. Never imported by runtime investigators."""

import json
from pathlib import Path
from typing import Any


def load_labels(path: Path) -> list[dict[str, Any]]:
    labels = [json.loads(line) for line in path.read_text().splitlines()]
    required = {"scenario_id", "tenant", "family", "episode", "verdict", "annotation"}
    if any(
        not required.issubset(row) or row["verdict"] not in ("malicious", "benign", "needs_review")
        for row in labels
    ):
        raise ValueError("Invalid evaluation labels")
    if len({row["scenario_id"] for row in labels}) != len(labels):
        raise ValueError("Repeated scenario identity")
    return labels
