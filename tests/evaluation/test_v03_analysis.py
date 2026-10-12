import hashlib
import json
import runpy
from pathlib import Path

import pytest

ANALYSIS = runpy.run_path(str(Path(__file__).parents[2] / "scripts/summarize_v03.py"))


@pytest.mark.parametrize("mutation", ["unfinished", "content", "code"])
def test_v03_analysis_refuses_incomplete_or_changed_studies(tmp_path, mutation):
    data = b"{}\n"
    (tmp_path / "summary.json").write_bytes(data)
    manifest = {
        "git": {"sha": ANALYSIS["FROZEN_COMMIT"], "dirty": False},
        "model": "openai/gpt-4.1-mini",
        "status": "complete",
        "artifact_sha256": {"summary.json": hashlib.sha256(data).hexdigest()},
    }
    if mutation == "unfinished":
        manifest["status"] = "running"
    elif mutation == "content":
        (tmp_path / "summary.json").write_bytes(b"changed")
    else:
        manifest["git"]["sha"] = "unrecognized"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        ANALYSIS["validate_run"](tmp_path)
