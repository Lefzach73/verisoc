import asyncio
import json
from uuid import uuid4

import httpx
import pytest

from verisoc.core.ids import demo_tenant
from verisoc.detection.rules import detect
from verisoc.investigation.pipeline import candidate, investigate
from verisoc.llm.base import Budget, ProviderReply, ToolCall
from verisoc.llm.mock import MockProvider
from verisoc.llm.openai_compatible import OpenAICompatibleProvider
from verisoc.llm.validation import parse_candidate


class BrokenProvider(MockProvider):
    def __init__(self, failure):
        self.failure = failure
        self.called = False

    async def generate(self, messages, budget, seed):
        self.called = True
        if self.failure == "timeout":
            await asyncio.sleep(0.2)
        if self.failure == "oversized":
            return ProviderReply(content="x" * 70000, tokens_input=1, tokens_output=1)
        if self.failure == "usage":
            return ProviderReply(content="{}", tokens_input=1000000, tokens_output=1000000)
        if self.failure == "tool":
            return ProviderReply(
                content="",
                tool_calls=(ToolCall(call_id="1", name="shell", arguments={"command": "inert"}),),
                tokens_input=1,
                tokens_output=1,
            )
        if self.failure == "foreign":
            return ProviderReply(
                content="",
                tool_calls=(
                    ToolCall(
                        call_id="1", name="get_evidence", arguments={"event_ids": [str(uuid4())]}
                    ),
                ),
                tokens_input=1,
                tokens_output=1,
            )
        return ProviderReply(content='{ "claims":', tokens_input=1, tokens_output=1)


@pytest.mark.parametrize(
    "failure", ["timeout", "oversized", "usage", "tool", "foreign", "malformed"]
)
def test_08_failures_produce_review_and_typed_limit(db, failure):
    with db.scope(demo_tenant("demo-a")) as repo:
        case = detect(repo, "demo")[0]
        report = investigate(repo, case, BrokenProvider(failure), Budget(max_seconds=0.05))
        assert report.verdict == "needs_review" and report.limit_reasons
        assert not report.verified_claims
        assert report.tokens_input >= 0 and report.estimated_usd >= 0


def test_cost_preflight_prevents_call(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        provider = BrokenProvider("malformed")
        provider.input_usd_per_million = 10
        report = investigate(repo, detect(repo, "demo")[0], provider, Budget(max_usd=0))
        assert not provider.called and report.limit_reasons == ("cost_preflight",)


def test_oversized_input_prevents_call(db):
    with db.scope(demo_tenant("demo-a")) as repo:
        provider = BrokenProvider("malformed")
        report = investigate(repo, detect(repo, "demo")[0], provider, Budget(max_input_tokens=1))
        assert not provider.called and report.limit_reasons == ("input_tokens_preflight",)


def test_network_requires_opt_in_and_prices():
    with pytest.raises(ValueError, match="opt-in"):
        OpenAICompatibleProvider(endpoint="http://localhost:8080/v1", model="example")
    with pytest.raises(ValueError, match="Hosted"):
        OpenAICompatibleProvider(
            endpoint="http://remote.invalid/v1", model="example", allow_network=True
        )
    with pytest.raises(ValueError, match="price snapshot"):
        OpenAICompatibleProvider(
            endpoint="https://remote.invalid/v1",
            model="example",
            allow_network=True,
            allow_hosted=True,
        )
    with pytest.raises(ValueError, match="endpoint"):
        OpenAICompatibleProvider(
            endpoint="https://user:secret@remote.invalid/v1", model="x", allow_network=True
        )


@pytest.mark.parametrize(
    "status,body",
    [(429, {}), (503, {}), (200, {}), (200, {"choices": [{"message": {"content": "{}"}}]})],
)
def test_adapter_failure_statuses_and_missing_usage(db, status, body):
    transport = httpx.MockTransport(lambda request: httpx.Response(status, json=body))
    adapter = OpenAICompatibleProvider(
        endpoint="http://127.0.0.1:8080/v1",
        model="synthetic-test",
        allow_network=True,
        transport=transport,
    )
    with db.scope(demo_tenant("demo-a")) as repo:
        report = investigate(repo, detect(repo, "demo")[0], adapter, Budget(max_input_tokens=65536))
        assert report.verdict == "needs_review" and report.limit_reasons


def test_adapter_actual_structured_reply_no_network(db):
    def handler(request):
        payload = json.loads(request.content)
        assert payload["seed"] == 20261011 and payload["tools"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"content": '{"claims":[],"proposed_verdict":"needs_review"}'}}
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            },
        )

    adapter = OpenAICompatibleProvider(
        endpoint="http://localhost:8080/v1",
        model="test-model",
        allow_network=True,
        transport=httpx.MockTransport(handler),
    )
    with db.scope(demo_tenant("demo-a")) as repo:
        result = asyncio.run(
            candidate(repo, detect(repo, "demo")[0], adapter, Budget(max_input_tokens=65536))
        )
        assert result.tokens_input == 10 and result.tokens_output == 5 and not result.limits


@pytest.mark.parametrize(
    "content",
    [
        '{"claims":[],"claims":[],"proposed_verdict":"malicious"}',
        '{"claims":[],"proposed_verdict":"benign","score":NaN}',
        '{"claims":[],"proposed_verdict":"benign","x":' + "[" * 20 + "0" + "]" * 20 + "}",
    ],
)
def test_json_duplicates_depth_nonfinite_rejected(content):
    with pytest.raises(ValueError):
        parse_candidate(content, 65536)


def test_complete_json_fence_only_is_normalized():
    body = '{"claims":[],"proposed_verdict":"needs_review"}'
    assert parse_candidate("```json\n" + body + "\n```", 65536).claims == ()
    with pytest.raises(ValueError):
        parse_candidate("prose ```json\n" + body + "\n``` trailing", 65536)
