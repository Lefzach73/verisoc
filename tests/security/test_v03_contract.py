from copy import deepcopy

from verisoc.core.models import CandidateReport
from verisoc.llm.schema import strict_wire_schema
from verisoc.verification.predicates import ALLOWED_ARGS


def test_provider_schema_expresses_distinct_predicate_arguments():
    schema = strict_wire_schema(CandidateReport.model_json_schema())
    branches = schema["$defs"]["CandidateClaim"].get("anyOf", [])
    assert len(branches) == len(ALLOWED_ARGS)
    for branch in branches:
        kind = branch["properties"]["claim_kind"]["enum"][0]
        parameters = branch["properties"].get("parameters")
        if ALLOWED_ARGS[kind]:
            assert set(parameters["properties"]) == ALLOWED_ARGS[kind]
            assert parameters["additionalProperties"] is False
        else:
            assert parameters is None


def test_wire_schema_conversion_does_not_mutate_runtime_contract():
    schema = CandidateReport.model_json_schema()
    before = deepcopy(schema)
    strict_wire_schema(schema)
    assert schema == before


def test_output_quota_is_bound_to_signal_and_enforced_in_wire_schema(db):
    import json

    from verisoc.core.ids import demo_tenant
    from verisoc.detection.rules import detect
    from verisoc.investigation.prompts import messages
    from verisoc.llm.base import Budget
    from verisoc.llm.openai_compatible import OpenAICompatibleProvider

    with db.scope(demo_tenant("demo-a")) as repo:
        case = next(c for c in detect(repo, "demo") if c.alert.rule_id == "lab_process")
        history = messages(case, [])
        control = json.loads(history[1]["content"])
        assert control["claim_limit"] == 3
        provider = OpenAICompatibleProvider(
            endpoint="http://localhost:8080/v1", model="test", allow_network=True
        )
        payload = provider.payload(history, Budget(), 42)
        assert (
            payload["response_format"]["json_schema"]["schema"]["properties"]["claims"]["maxItems"]
            == 3
        )
        submission = next(
            t for t in payload["tools"] if t["function"]["name"] == "submit_candidate_report"
        )
        assert submission["function"]["parameters"]["properties"]["claims"]["maxItems"] == 3
