import json
from typing import Any

from verisoc.core.models import CandidateReport


def parse_candidate(content: str, max_bytes: int) -> CandidateReport:
    if len(content.encode()) > max_bytes:
        raise ValueError("Oversized model output")

    # Accept one complete Markdown JSON fence from providers without JSON+tool mode.
    # No substring extraction, semantic repair, or trailing prose is accepted.
    stripped = content.strip()
    if stripped.startswith("```json\n") and stripped.endswith("\n```"):
        content = stripped[8:-4]

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate JSON field")
            obj[key] = value
        return obj

    def invalid_constant(value: str) -> Any:
        raise ValueError("Nonfinite JSON constant")

    def depth(value: Any, level: int) -> None:
        if level > 16:
            raise ValueError("JSON depth exceeded")
        if isinstance(value, dict):
            for nested in value.values():
                depth(nested, level + 1)
        elif isinstance(value, list):
            for nested in value:
                depth(nested, level + 1)

    parsed = json.loads(content, object_pairs_hook=unique, parse_constant=invalid_constant)
    depth(parsed, 0)
    return CandidateReport.model_validate(parsed)
