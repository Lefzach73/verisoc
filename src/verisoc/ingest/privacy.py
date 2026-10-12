import re
from uuid import UUID

from verisoc.core.provenance import digest


def identifier(value: str | None, tenant: UUID) -> str | None:
    return "id-" + digest(f"{tenant}:{value}".encode())[:24] if value else None


def scrub(value: str) -> str:
    value = re.sub(r"(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*\S+", "[REDACTED]", value)
    value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[EMAIL]", value)
    return "".join(c for c in value if c >= " " or c in "\n\t")[:2048]
