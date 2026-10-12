"""Independent recomputation: no import or call of candidate derivation functions."""

import ntpath
from datetime import timedelta

from verisoc.core.errors import VeriSOCError
from verisoc.core.models import CanonicalEvent, Case
from verisoc.evidence.models import (
    FactArguments,
    FactCandidate,
    FactCheck,
    VerifiedFact,
    fact_context,
    fact_identity,
)
from verisoc.evidence.rules import RULES, RULESET_VERSION
from verisoc.evidence.source import input_hash, proof, read_case_events
from verisoc.storage.repository import Repository


def reject(reason: str) -> FactCheck:
    return FactCheck(status="rejected", reason_code=reason)


def recompute(
    case: Case, fact: FactCandidate, all_rows: list[CanonicalEvent], cited: list[CanonicalEvent]
) -> bool:
    """Recompute predicates and complete aggregate membership from authorized records."""
    args = fact.arguments
    expected_rows: list[CanonicalEvent] = []
    expected: FactArguments | None = None
    if fact.predicate == "observed_event" and len(cited) == 1:
        event = cited[0]
        expected_rows = [event]
        expected = FactArguments(
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
    elif fact.predicate == "windows_image_match" and len(cited) == 1:
        event = cited[0]
        if event.attributes.event_code != 4688 or not event.process_name:
            return False
        if ntpath.basename(event.process_name).casefold() != "lab-indicator.exe":
            return False
        expected_rows = [event]
        expected = FactArguments(
            host_id=event.host_id,
            process_name="lab-indicator.exe",
            start_at=event.occurred_at,
            end_at=event.occurred_at,
            event_count=1,
        )
    elif fact.predicate in (
        "failed_login_burst",
        "multi_account_failures",
        "source_account_failures",
        "success_after_failures",
    ):
        rule = RULES[fact.derivation_rule_id]
        if not args.host_id or not case.start_at <= args.start_at <= args.end_at <= case.end_at:
            return False
        if args.start_at != max(
            case.start_at, args.end_at - timedelta(seconds=rule.window_seconds)
        ):
            return False
        if fact.predicate in ("failed_login_burst", "success_after_failures") and not args.user_id:
            return False
        if fact.predicate == "source_account_failures" and args.src_ip is None:
            return False
        for event in all_rows:
            if (
                event.attributes.event_code != 4625
                or event.host_id != args.host_id
                or not event.user_id
            ):
                continue
            if not args.start_at <= event.occurred_at <= args.end_at:
                continue
            if (
                fact.predicate in ("failed_login_burst", "success_after_failures")
                and event.user_id != args.user_id
            ):
                continue
            if fact.predicate == "source_account_failures" and event.src_ip != args.src_ip:
                continue
            if fact.predicate == "success_after_failures" and event.occurred_at == args.end_at:
                continue
            expected_rows.append(event)
        failures = len(expected_rows)
        users = len({e.user_id for e in expected_rows})
        if failures < rule.minimum_count or users < rule.minimum_distinct_users:
            return False
        if fact.predicate == "success_after_failures":
            successes = [e for e in cited if e.attributes.event_code == 4624]
            if len(successes) != 1:
                return False
            success = successes[0]
            if (
                success.host_id != args.host_id
                or success.user_id != args.user_id
                or success.occurred_at != args.end_at
            ):
                return False
            expected_rows.append(success)
        expected = FactArguments(
            host_id=args.host_id,
            user_id=args.user_id
            if fact.predicate in ("failed_login_burst", "success_after_failures")
            else None,
            src_ip=args.src_ip if fact.predicate == "source_account_failures" else None,
            distinct_users=users
            if fact.predicate in ("multi_account_failures", "source_account_failures")
            else None,
            start_at=args.start_at,
            end_at=args.end_at,
            event_count=len(expected_rows),
        )
    expected_rows.sort(key=lambda e: (e.occurred_at, str(e.event_id)))
    return (
        expected is not None
        and args == expected
        and tuple(e.event_id for e in expected_rows) == fact.source_event_ids
    )


def verify_one(
    repo: Repository,
    case: Case,
    candidate: FactCandidate,
    records: list[CanonicalEvent],
    fingerprint: str,
) -> FactCheck:
    try:
        candidate = FactCandidate.model_validate(
            candidate.model_dump(mode="json", exclude={"verification_status"})
        )
        if (
            candidate.tenant_id != repo.tenant
            or candidate.case_id != case.case_id
            or candidate.dataset_id != case.dataset_id
        ):
            return reject("fact_unavailable")
        if candidate.input_hash != fingerprint:
            return reject("source_snapshot_changed")
        by_id = {e.event_id: e for e in records}
        if any(e not in by_id for e in candidate.source_event_ids):
            return reject("source_unavailable")
        cited = [by_id[e] for e in candidate.source_event_ids]
        if candidate.evidence_hashes != tuple(proof(e) for e in cited):
            return reject("source_hash_mismatch")
        if candidate.fact_id != fact_identity(candidate.model_dump(mode="json")):
            return reject("fact_identity_mismatch")
        rule = RULES.get(candidate.derivation_rule_id)
        if (
            not rule
            or rule.version != candidate.derivation_rule_version
            or rule.predicate != candidate.predicate
        ):
            return reject("unknown_derivation")
        if not recompute(case, candidate, records, cited):
            return reject("derivation_mismatch")
        verified = VerifiedFact.model_validate(
            {**candidate.model_dump(mode="json"), "verification_status": "verified"},
            context=fact_context(),
        )
        return FactCheck(
            status="verified", reason_code="source_and_derivation_verified", verified_fact=verified
        )
    except (ValueError, VeriSOCError):
        return reject("source_unavailable")


def verify_facts(
    repo: Repository, case: Case, candidates: tuple[FactCandidate, ...]
) -> tuple[FactCheck, ...]:
    try:
        repo._scope(case)
        records = read_case_events(repo, case)
        fingerprint = input_hash(case, records, RULESET_VERSION)
    except (ValueError, VeriSOCError):
        return tuple(reject("source_unavailable") for _ in candidates)
    return tuple(verify_one(repo, case, f, records, fingerprint) for f in candidates)


def verify_fact(repo: Repository, case: Case, candidate: FactCandidate) -> FactCheck:
    return verify_facts(repo, case, (candidate,))[0]
