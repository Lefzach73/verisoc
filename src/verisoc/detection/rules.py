"""Native deterministic rules; not a Sigma engine and not proof of malicious intent."""

from collections import defaultdict, deque
from datetime import timedelta
from itertools import groupby

from verisoc.core.ids import stable_id
from verisoc.core.models import Alert, CanonicalEvent, Case
from verisoc.storage.repository import Repository

RULE_VERSION = "native-1.1"
APPROVED_RULES = {"auth_burst", "auth_success_after_failures", "lab_process"}


def make_case(evidence: list[CanonicalEvent], rule: str, title: str, severity: str) -> Case:
    evidence = sorted(evidence, key=lambda e: (e.occurred_at, str(e.event_id)))
    first, last = evidence[0], evidence[-1]
    ids = tuple(e.event_id for e in evidence)
    case_id = stable_id(
        first.tenant_id, first.dataset_id, RULE_VERSION, rule, *sorted(map(str, ids))
    )
    alert = Alert.model_validate(
        dict(
            alert_id=case_id,
            tenant_id=first.tenant_id,
            dataset_id=first.dataset_id,
            rule_id=rule,
            rule_version=RULE_VERSION,
            title=title,
            severity=severity,
            event_ids=ids,
            start_at=first.occurred_at,
            end_at=last.occurred_at,
        )
    )
    return Case(
        case_id=case_id,
        tenant_id=first.tenant_id,
        dataset_id=first.dataset_id,
        event_ids=ids,
        start_at=first.occurred_at,
        end_at=last.occurred_at,
        alert=alert,
    )


def detect(repo: Repository, dataset: str, *, correlation: bool = True) -> list[Case]:
    records = repo.list_events(dataset)
    grouped: dict[tuple[str, str], list[CanonicalEvent]] = defaultdict(list)
    result: list[Case] = []
    for event in records:
        if event.source_kind == "windows_process" and event.process_name == "lab-indicator.exe":
            result.append(make_case([event], "lab_process", "Laboratory process indicator", "high"))
        if event.source_kind == "windows_auth" and event.host_id and event.user_id:
            grouped[(event.host_id, event.user_id)].append(event)
    for group in grouped.values():
        window: deque[CanonicalEvent] = deque()
        pending: deque[CanonicalEvent] = deque()
        # Group equal timestamps so arrival/UUID order never invents chronology.
        for timestamp, same_time in groupby(group, key=lambda e: e.occurred_at):
            batch = list(same_time)
            boundary = timestamp - timedelta(minutes=5)
            while window and window[0].occurred_at < boundary:
                window.popleft()
            while pending and pending[0].occurred_at < boundary:
                pending.popleft()
            if correlation and len(window) >= 5:
                # Bounded witness set: enough real records for the predicate, never invented counts.
                evidence = list(window)[-32:]
                for success in (e for e in batch if e.outcome == "success"):
                    result.append(
                        make_case(
                            evidence + [success],
                            "auth_success_after_failures",
                            "Success after repeated failures",
                            "high",
                        )
                    )
            failures = [e for e in batch if e.outcome == "failure"]
            window.extend(failures)
            pending.extend(failures)
            if len(pending) >= 5:
                # Retain up to 32 actual witness references; this is not a total count.
                result.append(
                    make_case(
                        list(pending)[-32:], "auth_burst", "Repeated login failures", "medium"
                    )
                )
                pending.clear()
    unique = {case.case_id: case for case in result}
    for case in unique.values():
        repo.put_case(case)
    return sorted(unique.values(), key=lambda c: str(c.case_id))


def qualified_signal(case: Case, evidence: list[CanonicalEvent]) -> bool:
    """Validate rule semantics independently of supplied rule name/severity."""
    if not case.alert or not evidence or case.alert.severity != "high":
        return False
    if set(e.event_id for e in evidence) != set(case.alert.event_ids):
        return False
    if case.alert.rule_id == "lab_process":
        return all(
            e.source_kind == "windows_process" and e.process_name == "lab-indicator.exe"
            for e in evidence
        )
    if case.alert.rule_id == "auth_success_after_failures":
        failed = [e for e in evidence if e.source_kind == "windows_auth" and e.outcome == "failure"]
        succeeded = [
            e for e in evidence if e.source_kind == "windows_auth" and e.outcome == "success"
        ]
        if len(failed) < 5 or len(succeeded) != 1:
            return False
        success = succeeded[0]
        return bool(
            success.host_id
            and success.user_id
            and all(
                e.host_id == success.host_id
                and e.user_id == success.user_id
                and success.occurred_at - timedelta(minutes=5)
                <= e.occurred_at
                < success.occurred_at
                for e in failed
            )
        )
    return False
