from verisoc.core.models import CandidateClaim, CanonicalEvent

OBSERVED = {
    "observed_login_failure": ("windows_auth", "failure"),
    "observed_login_success": ("windows_auth", "success"),
    "observed_process": ("windows_process", "success"),
    "observed_network_connection": ("network_flow", "success"),
}
ALLOWED_ARGS = {
    "observed_login_failure": {"host_id", "user_id", "start_at", "end_at"},
    "observed_login_success": {"host_id", "user_id", "start_at", "end_at"},
    "observed_process": {"host_id", "process_name", "start_at", "end_at"},
    "observed_network_connection": {"src_ip", "dst_ip", "dst_port", "start_at", "end_at"},
    "shared_host": set(),
    "shared_user": set(),
    "temporal_order": set(),
    "analyst_inference": set(),
}


def check(claim: CandidateClaim, events: list[CanonicalEvent]) -> tuple[str, str]:
    kind = claim.claim_kind
    args = claim.parameters.model_dump(exclude_none=True)
    if not set(args).issubset(ALLOWED_ARGS[kind]):
        return "rejected", "unsupported_argument"
    if kind == "analyst_inference":
        return "insufficient", "interpretation_not_provable"
    if kind in OBSERVED:
        if len(events) != 1:
            return "rejected", "predicate_arity"
        event = events[0]
        if (event.source_kind, event.outcome) != OBSERVED[kind]:
            return "rejected", "predicate_mismatch"
        for name, value in args.items():
            if name == "start_at":
                if event.occurred_at < value:
                    return "rejected", "predicate_mismatch"
            elif name == "end_at":
                if event.occurred_at > value:
                    return "rejected", "predicate_mismatch"
            elif getattr(event, name) != value:
                return "rejected", "predicate_mismatch"
        return "verified", "predicate_supported"
    if kind in ("shared_host", "shared_user"):
        if len(events) < 2 or len({e.event_id for e in events}) != len(events):
            return "rejected", "predicate_arity"
        values = [getattr(e, "host_id" if kind == "shared_host" else "user_id") for e in events]
        if any(v is None for v in values):
            return "insufficient", "missing_field"
        return (
            ("verified", "predicate_supported")
            if len(set(values)) == 1
            else ("rejected", "predicate_mismatch")
        )
    if len(events) != 2 or events[0].event_id == events[1].event_id:
        return "rejected", "predicate_arity"
    return (
        ("verified", "predicate_supported")
        if events[0].occurred_at < events[1].occurred_at
        else ("rejected", "chronology_not_strict")
    )
