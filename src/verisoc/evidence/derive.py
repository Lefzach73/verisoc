"""Trusted candidate derivation. Candidates still require independent recomputation."""

import ntpath
from collections import defaultdict
from datetime import timedelta
from typing import Any
from uuid import UUID

from verisoc.core.models import CanonicalEvent, Case
from verisoc.evidence.models import FactArguments, FactCandidate, Predicate, fact_identity
from verisoc.evidence.rules import RULES
from verisoc.evidence.source import proof


def propose_fact(
    case: Case,
    predicate: Predicate,
    arguments: FactArguments,
    records: list[CanonicalEvent],
    rule: str,
    version: str,
    fingerprint: str,
) -> FactCandidate:
    records = sorted(records, key=lambda e: (e.occurred_at, str(e.event_id)))
    candidate = FactCandidate(
        fact_id=UUID(int=0),
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        dataset_id=case.dataset_id,
        predicate=predicate,
        arguments=arguments,
        source_event_ids=tuple(e.event_id for e in records),
        derivation_rule_id=rule,
        derivation_rule_version=version,
        evidence_hashes=tuple(proof(e) for e in records),
        input_hash=fingerprint,
    )
    return candidate.model_copy(
        update={"fact_id": fact_identity(candidate.model_dump(mode="json"))}
    )


def derive(
    case: Case, records: list[CanonicalEvent], fingerprint: str
) -> tuple[FactCandidate, ...]:
    facts = []
    for event in records:
        args = FactArguments(
            event_code=event.attributes.event_code,
            outcome=event.outcome,
            host_id=event.host_id,
            user_id=event.user_id,
            process_name=event.process_name,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            start_at=event.occurred_at,
            end_at=event.occurred_at,
            event_count=1,
        )
        facts.append(
            propose_fact(
                case, "observed_event", args, [event], "record-observation", "1.0", fingerprint
            )
        )
    facts.extend(derive_indicators(case, records, fingerprint))
    return tuple(facts)


def best_window(records: list[CanonicalEvent], distinct: bool = False) -> list[CanonicalEvent]:
    """One deterministic maximal witness per join group; count every qualifying source record."""
    best: list[CanonicalEvent] = []
    for event in records:
        start = event.occurred_at - timedelta(seconds=300)
        window = [e for e in records if start <= e.occurred_at <= event.occurred_at]
        score = len({e.user_id for e in window}) if distinct else len(window)
        previous = len({e.user_id for e in best}) if distinct else len(best)
        if (score, len(window)) > (previous, len(best)):
            best = window
    return best


def derive_indicators(
    case: Case, records: list[CanonicalEvent], fingerprint: str
) -> list[FactCandidate]:
    result: list[FactCandidate] = []
    groups: dict[tuple[str, tuple[str, ...]], list[CanonicalEvent]] = defaultdict(list)
    for event in records:
        if (
            event.attributes.event_code == 4688
            and event.process_name
            and (ntpath.basename(event.process_name).casefold() == "lab-indicator.exe")
        ):
            args = FactArguments(
                host_id=event.host_id,
                process_name="lab-indicator.exe",
                start_at=event.occurred_at,
                end_at=event.occurred_at,
                event_count=1,
            )
            result.append(
                propose_fact(
                    case,
                    "windows_image_match",
                    args,
                    [event],
                    "windows-lab-image",
                    "1.0",
                    fingerprint,
                )
            )
        if event.attributes.event_code != 4625 or not event.host_id or not event.user_id:
            continue
        groups[("auth-failure-count", (event.host_id, event.user_id))].append(event)
        groups[("host-account-failure-count", (event.host_id,))].append(event)
        if event.src_ip:
            groups[("source-account-failure-count", (event.host_id, str(event.src_ip)))].append(
                event
            )
    for (rule_id, _), failures in groups.items():
        rule = RULES[rule_id]
        evidence = best_window(failures, rule.semantics == "value_count")
        users = len({e.user_id for e in evidence})
        if len(evidence) < rule.minimum_count or users < rule.minimum_distinct_users:
            continue
        first, last = evidence[0], evidence[-1]
        extra: dict[str, Any] = {"host_id": first.host_id}
        if rule_id == "auth-failure-count":
            extra["user_id"] = first.user_id
        else:
            extra["distinct_users"] = users
        if rule_id == "source-account-failure-count":
            extra["src_ip"] = first.src_ip
        args = FactArguments(
            start_at=max(case.start_at, last.occurred_at - timedelta(seconds=300)),
            end_at=last.occurred_at,
            event_count=len(evidence),
            **extra,
        )
        result.append(
            propose_fact(case, rule.predicate, args, evidence, rule_id, rule.version, fingerprint)
        )
    for success in (
        e for e in records if e.attributes.event_code == 4624 and e.host_id and e.user_id
    ):
        start = max(case.start_at, success.occurred_at - timedelta(seconds=300))
        failures = [
            e
            for e in records
            if e.attributes.event_code == 4625
            and e.host_id == success.host_id
            and e.user_id == success.user_id
            and start <= e.occurred_at < success.occurred_at
        ]
        if len(failures) < 5:
            continue
        args = FactArguments(
            host_id=success.host_id,
            user_id=success.user_id,
            start_at=start,
            end_at=success.occurred_at,
            event_count=len(failures) + 1,
        )
        result.append(
            propose_fact(
                case,
                "success_after_failures",
                args,
                failures + [success],
                "ordered-auth-sequence",
                "1.0",
                fingerprint,
            )
        )
    return result
