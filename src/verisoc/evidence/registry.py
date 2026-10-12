"""Bounded, tenant/case/content-bound cache; every cache hit is independently reverified."""

from collections import OrderedDict
from threading import RLock
from uuid import UUID

from verisoc.core.errors import NotFound
from verisoc.core.models import Case
from verisoc.evidence.derive import derive
from verisoc.evidence.models import FactCandidate, VerifiedFact
from verisoc.evidence.rules import RULESET_VERSION
from verisoc.evidence.source import input_hash, read_case_events
from verisoc.storage.repository import Repository
from verisoc.verification.facts import verify_fact, verify_facts


class FactCache:
    def __init__(self, capacity: int = 16) -> None:
        if not 1 <= capacity <= 64:
            raise ValueError("Invalid cache capacity")
        self.capacity = capacity
        self.lock = RLock()
        self.entries: OrderedDict[tuple[UUID, UUID, str], tuple[FactCandidate, ...]] = OrderedDict()

    def get(self, key: tuple[UUID, UUID, str]) -> tuple[FactCandidate, ...] | None:
        with self.lock:
            value = self.entries.get(key)
            if value is not None:
                self.entries.move_to_end(key)
            return value

    def put(self, key: tuple[UUID, UUID, str], facts: tuple[FactCandidate, ...]) -> None:
        with self.lock:
            self.entries[key] = facts
            self.entries.move_to_end(key)
            while len(self.entries) > self.capacity:
                self.entries.popitem(last=False)


class EvidenceRegistry:
    def __init__(self, repo: Repository, case: Case, cache: FactCache | None = None) -> None:
        self.repo, self.case = repo, case
        records = read_case_events(repo, case)
        self.input_hash = input_hash(case, records, RULESET_VERSION)
        key = (repo.tenant, case.case_id, self.input_hash)
        proposed = cache.get(key) if cache else None
        if proposed is None:
            proposed = derive(case, records, self.input_hash)
            if cache:
                cache.put(key, proposed)
        self.facts: dict[UUID, VerifiedFact] = {}
        self.rejections: list[str] = []
        for result in verify_facts(repo, case, proposed):
            if result.verified_fact:
                self.facts[result.verified_fact.fact_id] = result.verified_fact
            else:
                self.rejections.append(result.reason_code)

    def get(self, fact_id: UUID) -> VerifiedFact:
        if fact_id not in self.facts:
            raise NotFound("Fact unavailable")
        result = verify_fact(self.repo, self.case, self.facts[fact_id])
        if not result.verified_fact:
            raise NotFound("Fact unavailable")
        return result.verified_fact
