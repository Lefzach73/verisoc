import hashlib
import json
import runpy
from pathlib import Path

import pytest

SCRIPT = runpy.run_path(str(Path(__file__).parents[2] / "scripts/summarize_study.py"))


@pytest.mark.parametrize("mutation", ["content", "provenance", "path"])
def test_study_aggregation_rejects_tampered_inputs(tmp_path, mutation):
    content = b"original"
    (tmp_path / "metrics.json").write_bytes(content)
    manifest = {
        "git": {"sha": SCRIPT["FROZEN_SHA"], "dirty": False},
        "model": "openai/gpt-4.1-mini",
        "artifact_sha256": {"metrics.json": hashlib.sha256(content).hexdigest()},
    }
    if mutation == "content":
        (tmp_path / "metrics.json").write_bytes(b"modified")
    elif mutation == "provenance":
        manifest["git"]["dirty"] = True
    else:
        manifest["artifact_sha256"] = {"../metrics.json": "0" * 64}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        SCRIPT["read_run"](tmp_path)
