"""Optional official pySigma parsing; exact scalar process-name equality subset only."""

import importlib

import yaml

from verisoc.core.models import Case
from verisoc.detection.rules import make_case
from verisoc.storage.repository import Repository


def compile_rule(content: str) -> tuple[str, str]:
    if len(content.encode()) > 4096:
        raise ValueError("Rule too large")
    try:
        for event in yaml.parse(content):
            if isinstance(event, yaml.events.AliasEvent) or getattr(event, "anchor", None):
                raise ValueError("Unsupported Sigma YAML aliases/anchors")
        obj = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError("Unsupported or malformed Sigma YAML") from exc
    if not isinstance(obj, dict):
        raise ValueError("Rule object required")
    if not set(obj).issubset(
        {"title", "id", "status", "description", "logsource", "detection", "level"}
    ):
        raise ValueError("Unsupported Sigma metadata/features")
    if not obj.get("id"):
        raise ValueError("Explicit rule UUID required")
    detection = obj.get("detection", {})
    if not isinstance(detection, dict):
        raise ValueError("Unsupported Sigma detection")
    if set(detection) != {"selection", "condition"} or detection["condition"] != "selection":
        raise ValueError("Unsupported Sigma condition")
    selection = detection["selection"]
    if not isinstance(selection, dict) or set(selection) != {"process_name"}:
        raise ValueError("Unsupported Sigma field/modifier")
    value = selection["process_name"]
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(c in value for c in "*?"):
        raise ValueError("Unsupported Sigma value/wildcard")
    if obj.get("logsource") != {"product": "windows", "category": "process_creation"}:
        raise ValueError("Unsupported Sigma logsource")
    # pySigma validates the real Sigma contract. No replacement parser/condition semantics.
    try:
        library = importlib.import_module("sigma.collection")
    except ImportError as exc:
        raise ValueError("Install optional extra: uv sync --extra sigma") from exc
    collection = library.SigmaCollection.from_yaml(content, collect_errors=False)
    if len(collection.rules) != 1:
        raise ValueError("One Sigma rule required")
    rule = collection.rules[0]
    item = rule.detection.detections["selection"].detection_items[0]
    if item.modifiers or len(item.value) != 1 or item.value[0].to_plain() != value:
        raise ValueError("Unsupported parsed Sigma semantics")
    return str(rule.id), value


def detect_sigma(repo: Repository, dataset: str, content: str) -> list[Case]:
    rule_id, process_name = compile_rule(content)
    cases = [
        make_case([event], "sigma:" + rule_id, "Exact process observation (Sigma subset)", "high")
        for event in repo.list_events(dataset)
        if event.source_kind == "windows_process" and event.process_name == process_name
    ]
    for case in cases:
        repo.put_case(case)
    return cases
