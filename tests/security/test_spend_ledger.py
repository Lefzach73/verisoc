import asyncio
import json
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from verisoc.core.errors import BudgetExceeded, ProviderFailure
from verisoc.llm.base import Budget
from verisoc.llm.ledger import SpendLedger
from verisoc.llm.openai_compatible import OpenAICompatibleProvider


def test_reservations_survive_crash_and_reopening(tmp_path):
    path = tmp_path / "spend.json"
    ledger = SpendLedger(path, 1)
    first = ledger.reserve(0.6, {"model": "test"})
    ledger.fail(first, "timeout")
    reopened = SpendLedger(path, 1)
    with pytest.raises(BudgetExceeded):
        reopened.reserve(0.5, {})
    assert reopened.snapshot()["committed_usd"] == "0.600000000"
    with pytest.raises(ValueError, match="Cannot change"):
        SpendLedger(path, 100)


def test_concurrent_reservations_cannot_overspend(tmp_path):
    path = tmp_path / "shared.json"

    def reserve(_):
        try:
            SpendLedger(path, 1).reserve(0.3, {})
            return True
        except BudgetExceeded:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(reserve, range(20))) == 3
    assert SpendLedger(path, 1).snapshot()["committed_usd"] == "0.900000000"


def test_settlement_releases_only_unused_reservation(tmp_path):
    ledger = SpendLedger(tmp_path / "study.json", 1)
    rid = ledger.reserve(0.9, {})
    ledger.settle(rid, 0.1, {"completion_id": "synthetic"})
    ledger.reserve(0.9, {})
    assert ledger.snapshot()["committed_usd"] == "1.000000000"
    with pytest.raises(ValueError, match="already finalized"):
        ledger.settle(rid, 0, {})


def test_openrouter_metering_routing_and_failed_content(tmp_path):
    ledger = SpendLedger(tmp_path / "study.json", 1)

    def transport(request):
        payload = json.loads(request.content)
        assert payload["provider"]["only"] == ["openai"]
        assert payload["provider"]["allow_fallbacks"] is False
        assert "tools" not in payload
        return httpx.Response(
            200,
            json={
                "id": "synthetic-request",
                "provider": "OpenAI",
                "model": "test-model",
                "choices": [
                    {"message": {"content": "not valid candidate json"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.00001},
            },
        )

    adapter = OpenAICompatibleProvider(
        endpoint="https://openrouter.ai/api/v1",
        model="test-model",
        allow_network=True,
        allow_hosted=True,
        input_usd_per_million=0.4,
        output_usd_per_million=1.6,
        price_snapshot="synthetic-price",
        ledger=ledger,
        routing_provider="openai",
        transport=httpx.MockTransport(transport),
    )
    reply = asyncio.run(adapter.generate([], Budget(max_tool_calls=0, max_usd=1), 1))
    assert reply.cost_usd == 0.00001 and reply.completion_id == "synthetic-request"
    state = ledger.snapshot()
    assert state["settled_usd"] == "0.000010000"
    assert state["requests"][0]["state"] == "settled"


def test_http_failure_does_not_release_potential_charge_and_redacts_key(tmp_path):
    ledger = SpendLedger(tmp_path / "study.json", 1)
    marker = "synthetic-secret-fixture-value"
    adapter = OpenAICompatibleProvider(
        endpoint="https://openrouter.ai/api/v1",
        model="test-model",
        allow_network=True,
        allow_hosted=True,
        api_key=marker,
        input_usd_per_million=0.4,
        output_usd_per_million=1.6,
        price_snapshot="synthetic",
        ledger=ledger,
        routing_provider="openai",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(429, json={"error": {"message": marker}})
        ),
    )
    with pytest.raises(ProviderFailure):
        asyncio.run(adapter.generate([], Budget(max_usd=1), 1))
    state = ledger.snapshot()
    assert state["requests"][0]["state"] == "unknown_cost"
    assert float(state["committed_usd"]) > 0
    assert marker not in json.dumps(state)


def test_strict_wire_schema_has_required_fields_without_mutating_runtime_schema():
    from verisoc.core.models import CandidateReport
    from verisoc.llm.schema import strict_wire_schema

    original = CandidateReport.model_json_schema()
    converted = strict_wire_schema(original)
    assert "uncertainties" not in original["required"]

    def check(value):
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert set(value["required"]) == set(value.get("properties", {}))
                assert value["additionalProperties"] is False
            assert "default" not in value
            assert value.get("format") != "ipvanyaddress"
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)

    check(converted)


def test_google_tool_mode_preserves_validation_without_json_mime_conflict(tmp_path):
    ledger = SpendLedger(tmp_path / "budget.json", 1)
    provider = OpenAICompatibleProvider(
        endpoint="https://openrouter.ai/api/v1",
        model="google/test",
        allow_network=True,
        allow_hosted=True,
        input_usd_per_million=0.3,
        output_usd_per_million=2.5,
        price_snapshot="test",
        ledger=ledger,
        routing_provider="google-ai-studio",
        reasoning_enabled=False,
    )
    tool_request = provider.payload([], Budget(), 1)
    assert "response_format" not in tool_request and tool_request["tools"]
    plain = provider.payload([], Budget(max_tool_calls=0), 1)
    assert "response_format" in plain and "tools" not in plain
