from copy import deepcopy
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import update

from verisoc.core.errors import NotFound
from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect
from verisoc.evidence.models import FactCandidate, VerifiedFact, fact_identity
from verisoc.evidence.registry import EvidenceRegistry, FactCache
from verisoc.storage.models import events
from verisoc.verification.facts import verify_fact


def packet(repo):
    case = detect(repo, "demo")[0]
    return case, EvidenceRegistry(repo, case)


def resign(data):
    data["fact_id"] = str(fact_identity(data))
    return FactCandidate.model_validate(data)


def test_facts_are_issued_by_independent_verification_only(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case, registry = packet(repo)
        fact = next(iter(registry.facts.values()))
        assert fact.verification_status == "verified"
        assert verify_fact(repo, case, fact).status == "verified"
        with pytest.raises(ValidationError, match="trusted"):
            VerifiedFact.model_validate(fact.model_dump(mode="json"))


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_field",
        "wrong_type",
        "missing_source",
        "bad_hash",
        "wrong_value",
        "wrong_tenant",
        "wrong_case",
        "bad_rule",
        "wrong_count",
    ],
)
def test_re_signed_fabrications_do_not_pass_semantic_verification(db, mutation):
    with db.scope(demo_tenant("demo-a")) as repo:
        case, registry = packet(repo)
        fact = next(iter(registry.facts.values()))
        data = fact.model_dump(mode="json", exclude={"verification_status"})
        if mutation == "unknown_field":
            data["arguments"]["invented_field"] = "trusted"
        elif mutation == "wrong_type":
            data["arguments"]["event_count"] = "1"
        elif mutation == "missing_source":
            missing = str(uuid4())
            data["source_event_ids"][0] = missing
            data["evidence_hashes"][0]["event_id"] = missing
        elif mutation == "bad_hash":
            data["evidence_hashes"][0]["canonical_sha256"] = "0" * 64
        elif mutation == "wrong_value":
            data["arguments"]["process_name"] = "invented.exe"
        elif mutation == "wrong_tenant":
            data["tenant_id"] = str(demo_tenant("demo-b"))
        elif mutation == "wrong_case":
            data["case_id"] = str(uuid4())
        elif mutation == "bad_rule":
            data["derivation_rule_version"] = "forged-1.0"
        else:
            data["arguments"]["event_count"] = 2
        if mutation in ("unknown_field", "wrong_type"):
            with pytest.raises(ValidationError):
                resign(data)
        else:
            assert verify_fact(repo, case, resign(data)).status == "rejected"


def test_original_record_change_invalidates_existing_fact_and_cache(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
        cache = FactCache()
        registry = EvidenceRegistry(repo, case, cache)
        fact = next(iter(registry.facts.values()))
        event = repo.get_event(fact.source_event_ids[0])
        data = deepcopy(event.model_dump(mode="json"))
        data["process_name"] = "substituted.exe"
        repo.conn.execute(
            update(events)
            .where(events.c.tenant_id == str(repo.tenant), events.c.event_id == str(event.event_id))
            .values(data=data)
        )
        assert verify_fact(repo, case, fact).status == "rejected"
        with pytest.raises(NotFound):
            registry.get(fact.fact_id)
        with pytest.raises(NotFound):
            EvidenceRegistry(repo, case, cache)


def test_same_names_other_tenant_cannot_share_facts_or_cache(db):
    cache = FactCache()
    with db.scope(demo_tenant("demo-a")) as repo:
        a, registry_a = packet(repo)
        fact = next(iter(registry_a.facts.values()))
        EvidenceRegistry(repo, a, cache)
    with db.scope(demo_tenant("demo-b")) as repo:
        b = detect(repo, "demo")[0]
        registry_b = EvidenceRegistry(repo, b, cache)
        assert fact.fact_id not in registry_b.facts
        assert verify_fact(repo, b, fact).status == "rejected"
        with pytest.raises(NotFound):
            registry_b.get(fact.fact_id)
        with pytest.raises(NotFound):
            registry_b.get(uuid4())


def test_wrong_producer_is_caught_by_independent_checker(db, monkeypatch):
    import verisoc.evidence.registry as module

    original = module.derive

    def faulty(case, rows, hash_value):
        facts = original(case, rows, hash_value)
        data = facts[0].model_dump(mode="json")
        data["arguments"]["event_count"] = 2
        return (resign(data),)

    monkeypatch.setattr(module, "derive", faulty)
    with db.scope(demo_tenant("demo-a")) as repo:
        _, registry = packet(repo)
        assert not registry.facts and registry.rejections == ["derivation_mismatch"]
