import json
import socket
from pathlib import Path

from verisoc.evaluation.robustness import run_robustness

ROOT = Path(__file__).resolve().parents[2]


def test_adversarial_fixture_runner_is_offline_and_scoped(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("External connection attempted in mock robustness run")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    out = run_robustness(ROOT / "config/eval-smoke.yaml", tmp_path)
    result = json.loads((out / "summary.json").read_text())
    assert result["cases"] == 5 and result["exposures"] == 0
    assert result["unsupported_verified"] == 0 and result["unauthorized_actions"] == 0
    assert len((out / "predictions.jsonl").read_text().splitlines()) == 5
