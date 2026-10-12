from pathlib import Path

from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect
from verisoc.evaluation.fact_oracle import RawFactOracle
from verisoc.evidence.models import FactCandidate, fact_identity
from verisoc.evidence.registry import EvidenceRegistry


def test_raw_oracle_independently_rejects_a_re_signed_semantic_lie(db):
    raw = (Path(__file__).resolve().parents[2] / "fixtures/demo/events.jsonl").read_bytes()
    oracle = RawFactOracle(raw)
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
        facts = EvidenceRegistry(repo, case).facts.values()
        assert facts
        for fact in facts:
            assert oracle.supports_fact(case, fact)
            data = fact.model_dump(mode="json", exclude={"verification_status"})
            data["arguments"]["event_count"] += 1
            data["fact_id"] = str(fact_identity(data))
            assert not oracle.supports_fact(case, FactCandidate.model_validate(data))


def test_raw_oracle_does_not_trust_provenance_hashes_from_runtime(db):
    raw = (Path(__file__).resolve().parents[2] / "fixtures/demo/events.jsonl").read_bytes()
    oracle = RawFactOracle(raw)
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
        fact = next(iter(EvidenceRegistry(repo, case).facts.values()))
        for field in ("raw_row_sha256", "file_sha256", "canonical_sha256"):
            data = fact.model_dump(mode="json", exclude={"verification_status"})
            data["evidence_hashes"][0][field] = "0" * 64
            data["fact_id"] = str(fact_identity(data))
            assert not oracle.supports_fact(case, FactCandidate.model_validate(data))
