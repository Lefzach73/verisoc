"""Differential verifier/oracle checks over every admitted record; no model calls."""

import argparse
import json
from collections import Counter
from pathlib import Path
from uuid import uuid4

from verisoc.core.ids import demo_tenant, stable_id
from verisoc.core.models import CandidateClaim, Case, PredicateArgs
from verisoc.evaluation.oracle import RawRecordOracle
from verisoc.ingest.importer import import_jsonl
from verisoc.llm.mock import observed
from verisoc.storage.repository import Database
from verisoc.verification.verifier import verify


def check_corpus(source: Path) -> dict:
    content = source.read_bytes()
    oracle = RawRecordOracle(content)
    tenants = sorted({json.loads(line)["fixture_tenant"] for line in content.splitlines()})
    database = Database("sqlite:///:memory:")
    counts = Counter()
    examples = []
    try:
        for tenant in tenants:
            with database.scope(demo_tenant(tenant)) as repo:
                import_jsonl(repo, content, "demo", fixture_tenant=tenant)
        for tenant in tenants:
            with database.scope(demo_tenant(tenant)) as repo:
                for event in repo.list_events("demo"):
                    case = Case(
                        case_id=stable_id("oracle-audit", event.event_id),
                        tenant_id=repo.tenant,
                        dataset_id="demo",
                        event_ids=(event.event_id,),
                        start_at=event.occurred_at,
                        end_at=event.occurred_at,
                    )
                    proposal = observed(event)
                    candidates = [("supported_observation", proposal)]
                    for kind in (
                        "observed_process",
                        "observed_login_failure",
                        "observed_login_success",
                        "observed_network_connection",
                    ):
                        if kind != proposal.claim_kind:
                            candidates.append(
                                (
                                    "wrong_event_semantics",
                                    CandidateClaim(
                                        claim_id=stable_id(event.event_id, kind, "negative"),
                                        claim_kind=kind,
                                        subject_event_ids=(event.event_id,),
                                    ),
                                )
                            )
                    candidates.append(
                        (
                            "missing_citation",
                            proposal.model_copy(update={"subject_event_ids": (uuid4(),)}),
                        )
                    )
                    candidates.append(
                        (
                            "wrong_field",
                            CandidateClaim(
                                claim_id=stable_id(event.event_id, "wrong-field"),
                                claim_kind="observed_process",
                                subject_event_ids=(event.event_id,),
                                parameters=PredicateArgs(process_name="absent-counterfactual.exe"),
                            ),
                        )
                    )
                    for label, claim in candidates:
                        runtime = verify(repo, case, claim).status == "verified"
                        raw_support = oracle.supports(case, claim)
                        expected = label == "supported_observation"
                        counts["total_checks"] += 1
                        counts[label] += 1
                        counts["verifier_oracle_disagreements"] += runtime != raw_support
                        counts["counterfactual_false_accepts"] += runtime and not expected
                        counts["supported_false_rejections"] += expected and not runtime
                        if (runtime != raw_support or runtime != expected) and len(examples) < 20:
                            examples.append(
                                {
                                    "event_id": str(event.event_id),
                                    "category": label,
                                    "runtime": runtime,
                                    "raw_oracle": raw_support,
                                }
                            )
    finally:
        database.engine.dispose()
    return {
        "scope": "Finite differential test over procedural public records, not universal proof",
        "source": str(source),
        "counts": dict(counts),
        "mismatches": examples,
        "passed": not examples,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("fixtures/v03/events.jsonl"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = check_corpus(args.source)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["counts"]))
    if not result["passed"]:
        raise SystemExit("Differential verification failed")
