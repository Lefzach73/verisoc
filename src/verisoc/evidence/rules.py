"""Versioned native contracts. Sigma-inspired semantics, not a Sigma conversion backend."""

from types import MappingProxyType
from typing import Literal

from verisoc.core.models import Frozen
from verisoc.evidence.models import Predicate

RULESET_VERSION = "evidence-1.1"
SUPPORTED_CORRELATIONS = frozenset({"event_count", "value_count", "temporal_ordered"})


class RuleSpec(Frozen):
    rule_id: str
    version: str = "1.0"
    predicate: Predicate
    semantics: Literal[
        "observation", "field_match", "event_count", "value_count", "temporal_ordered"
    ]
    required_fields: tuple[str, ...]
    group_by: tuple[str, ...]
    window_seconds: int = 0
    minimum_count: int = 1
    minimum_distinct_users: int = 1
    priority: Literal[0, 1, 2] = 0
    proves_intent: Literal[False] = False


RULES = MappingProxyType(
    {
        "record-observation": RuleSpec(
            rule_id="record-observation",
            predicate="observed_event",
            semantics="observation",
            required_fields=("event_code", "occurred_at"),
            group_by=("tenant_id", "event_id"),
        ),
        "auth-failure-count": RuleSpec(
            rule_id="auth-failure-count",
            predicate="failed_login_burst",
            semantics="event_count",
            required_fields=("event_code", "host_id", "user_id", "occurred_at"),
            group_by=("tenant_id", "host_id", "user_id"),
            window_seconds=300,
            minimum_count=5,
            priority=1,
        ),
        "host-account-failure-count": RuleSpec(
            rule_id="host-account-failure-count",
            predicate="multi_account_failures",
            semantics="value_count",
            required_fields=("event_code", "host_id", "user_id", "occurred_at"),
            group_by=("tenant_id", "host_id"),
            window_seconds=300,
            minimum_count=5,
            minimum_distinct_users=5,
            priority=1,
        ),
        "source-account-failure-count": RuleSpec(
            rule_id="source-account-failure-count",
            predicate="source_account_failures",
            semantics="value_count",
            required_fields=("event_code", "host_id", "user_id", "src_ip", "occurred_at"),
            group_by=("tenant_id", "host_id", "src_ip"),
            window_seconds=300,
            minimum_count=5,
            minimum_distinct_users=5,
            priority=1,
        ),
        "ordered-auth-sequence": RuleSpec(
            rule_id="ordered-auth-sequence",
            predicate="success_after_failures",
            semantics="temporal_ordered",
            required_fields=("event_code", "host_id", "user_id", "occurred_at"),
            group_by=("tenant_id", "host_id", "user_id"),
            window_seconds=300,
            minimum_count=5,
            priority=2,
        ),
        "windows-lab-image": RuleSpec(
            rule_id="windows-lab-image",
            predicate="windows_image_match",
            semantics="field_match",
            required_fields=("event_code", "process_name"),
            group_by=("tenant_id", "host_id"),
            priority=2,
        ),
    }
)


def require_capability(semantics: str, backend: str = "native-v04") -> None:
    if backend != "native-v04" or semantics not in SUPPORTED_CORRELATIONS:
        raise ValueError("Unsupported correlation/backend capability")
