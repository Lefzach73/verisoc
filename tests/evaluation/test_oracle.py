from pathlib import Path

from verisoc.core.ids import demo_tenant
from verisoc.core.models import CandidateReport, PredicateArgs
from verisoc.detection.rules import detect
from verisoc.evaluation.oracle import RawRecordOracle
from verisoc.llm.mock import observed
from verisoc.reporting.assemble import assemble

ROOT = Path(__file__).resolve().parents[2]


def test_oracle_disagrees_with_deliberately_broken_runtime_verifier(db, monkeypatch):
    import verisoc.verification.verifier as verifier

    oracle = RawRecordOracle((ROOT / "fixtures/demo/events.jsonl").read_bytes())
    with db.scope(demo_tenant("demo-a")) as repo:
        case = next(c for c in detect(repo, "demo") if c.alert.rule_id == "lab_process")
        claim = observed(repo.get_event(case.event_ids[0])).model_copy(
            update={"parameters": PredicateArgs(process_name="invented.exe")}
        )
        monkeypatch.setattr(
            verifier, "check", lambda claim, records: ("verified", "injected_test_fault")
        )
        report = assemble(
            repo, case, CandidateReport(claims=(claim,), proposed_verdict="malicious")
        )
        assert report.verified_claims[0].status == "verified"
        assert not oracle.supports(case, report.verified_claims[0].candidate)


def test_oracle_covers_all_real_observations_but_not_foreign_tenants(db):
    oracle = RawRecordOracle((ROOT / "fixtures/demo/events.jsonl").read_bytes())
    with db.scope(demo_tenant("demo-a")) as repo:
        for case in detect(repo, "demo"):
            for eid in case.event_ids:
                assert oracle.supports(case, observed(repo.get_event(eid)))
                foreign = case.model_copy(update={"tenant_id": demo_tenant("demo-b")})
                assert not oracle.supports(foreign, observed(repo.get_event(eid)))
