"""User-configured adapter only. No default network, retries, redirects or proxy inheritance."""

import ipaddress
import json
from typing import Any
from urllib.parse import urlparse

import httpx

from verisoc.core.errors import BudgetExceeded, ProviderFailure
from verisoc.core.models import CandidateReport
from verisoc.core.provenance import json_hash
from verisoc.ingest.privacy import scrub
from verisoc.investigation.tool_router import TOOL_SCHEMAS
from verisoc.llm.base import Budget, ProviderReply, ToolCall
from verisoc.llm.ledger import SpendLedger
from verisoc.llm.schema import constrain_claim_ids, strict_wire_schema


class OpenAICompatibleProvider:
    provider_id = "openai-compatible"

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        allow_network: bool = False,
        allow_hosted: bool = False,
        api_key: str | None = None,
        input_usd_per_million: float | None = None,
        output_usd_per_million: float | None = None,
        price_snapshot: str = "",
        transport: httpx.AsyncBaseTransport | None = None,
        ledger: SpendLedger | None = None,
        routing_provider: str | None = None,
        reasoning_enabled: bool | None = None,
    ) -> None:
        if not allow_network:
            raise ValueError("Network adapter requires explicit opt-in")
        url = urlparse(endpoint)
        if url.username or url.password or url.query or url.fragment or not url.hostname:
            raise ValueError("Invalid endpoint")
        try:
            local = ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            local = url.hostname == "localhost"
        if url.scheme not in ("http", "https") or (
            not local and (not allow_hosted or url.scheme != "https")
        ):
            raise ValueError("Hosted transmission requires explicit opt-in and HTTPS")
        if not local and (
            input_usd_per_million is None or output_usd_per_million is None or not price_snapshot
        ):
            raise ValueError("Hosted price snapshot required")
        if not local and ledger is None:
            raise ValueError("Hosted models require a shared study spend ledger")
        self.ledger = ledger
        self.routing_provider = routing_provider
        self.reasoning_enabled = reasoning_enabled
        self.is_openrouter = url.hostname == "openrouter.ai"
        if self.is_openrouter:
            self.provider_id = "openrouter"
            if not ledger or not routing_provider:
                raise ValueError("OpenRouter requires a shared spend ledger and pinned provider")
        self.endpoint = endpoint.rstrip("/") + "/chat/completions"
        self.model_id = model
        self.key, self.transport = api_key, transport
        self.input_usd_per_million = input_usd_per_million or 0.0
        self.output_usd_per_million = output_usd_per_million or 0.0
        if (
            not 0 <= self.input_usd_per_million < 1000
            or not 0 <= self.output_usd_per_million < 1000
        ):
            raise ValueError("Invalid price rates")
        self.price_snapshot = price_snapshot or "local-user-configured-zero-billing"

    def payload(self, messages: list[dict[str, Any]], budget: Budget, seed: int) -> dict[str, Any]:
        tools: list[dict[str, Any]] = [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": "Read-only bounded tool or candidate submission",
                    "parameters": schema.model_json_schema(),
                },
            }
            for name, schema in TOOL_SCHEMAS.items()
        ]
        payload: dict[str, Any] = {
            "model": self.model_id,
            "messages": messages,
            "temperature": 0,
            "seed": seed,
            "max_tokens": budget.max_output_tokens,
            "tools": tools if budget.max_tool_calls > 0 else [],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "candidate_report",
                    "schema": CandidateReport.model_json_schema(),
                },
            },
        }

        if not budget.max_tool_calls:
            payload.pop("tools")
        if self.is_openrouter:
            response_format = payload["response_format"]
            response_format["json_schema"]["schema"] = strict_wire_schema(
                CandidateReport.model_json_schema()
            )
            response_format["json_schema"]["strict"] = True
            pool = (
                json.loads(messages[1]["content"]).get("claim_id_pool")
                if len(messages) > 1
                else None
            )
            if pool and self.routing_provider == "openai":
                constrain_claim_ids(response_format["json_schema"]["schema"], pool)
            for tool in tools:
                tool["function"]["parameters"] = strict_wire_schema(tool["function"]["parameters"])
                tool["function"]["strict"] = True
                if (
                    pool
                    and self.routing_provider == "openai"
                    and tool["function"]["name"] == "submit_candidate_report"
                ):
                    constrain_claim_ids(tool["function"]["parameters"], pool)
            payload["provider"] = {
                "order": [self.routing_provider],
                "only": [self.routing_provider],
                "allow_fallbacks": False,
                "require_parameters": True,
                "data_collection": "deny",
                "max_price": {
                    "prompt": self.input_usd_per_million,
                    "completion": self.output_usd_per_million,
                },
            }
            if (
                self.routing_provider
                and self.routing_provider.startswith("google")
                and budget.max_tool_calls
            ):
                # Gemini rejects JSON response MIME mode combined with function calling.
                # Native submit_candidate_report remains schema constrained and locally validated.
                payload.pop("response_format")
                payload["tool_choice"] = "auto"
            if self.reasoning_enabled is not None:
                payload["reasoning"] = {"enabled": self.reasoning_enabled, "exclude": True}
        control = json.loads(messages[1]["content"]) if len(messages) > 1 else {}
        quota = control.get("claim_limit", 64)
        if not isinstance(quota, int) or not 1 <= quota <= 64:
            raise ValueError("Invalid candidate output quota")
        if "response_format" in payload:
            payload["response_format"]["json_schema"]["schema"]["properties"]["claims"][
                "maxItems"
            ] = quota
        for tool in payload.get("tools", []):
            if tool["function"]["name"] == "submit_candidate_report":
                tool["function"]["parameters"]["properties"]["claims"]["maxItems"] = quota
        return payload

    def input_upper_bound(self, messages: list[dict[str, Any]], budget: Budget, seed: int) -> int:
        return len(json.dumps(self.payload(messages, budget, seed), ensure_ascii=False).encode())

    async def generate(
        self, messages: list[dict[str, Any]], budget: Budget, seed: int
    ) -> ProviderReply:
        payload = self.payload(messages, budget, seed)
        headers = {"Authorization": "Bearer " + self.key} if self.key else {}
        reservation = None
        settled = False
        error_reason = "provider_unavailable_or_timeout"
        if self.ledger:
            reserve = (
                budget.max_input_tokens * self.input_usd_per_million
                + budget.max_output_tokens * self.output_usd_per_million
            ) / 1_000_000
            reservation = self.ledger.reserve(
                reserve,
                {
                    "model": self.model_id,
                    "provider": self.routing_provider,
                    "request_sha256": json_hash(payload),
                },
            )
        try:
            async with httpx.AsyncClient(
                timeout=budget.max_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
            ) as client:
                async with client.stream(
                    "POST", self.endpoint, json=payload, headers=headers
                ) as response:
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(data) + len(chunk) > budget.max_response_bytes:
                            raise BudgetExceeded("provider_output_bytes")
                        data.extend(chunk)
                    if response.status_code != 200:
                        error_reason = "provider_http_" + str(response.status_code)
                        # Diagnose schema incompatibility without exposing the credential.
                        try:
                            error = json.loads(data).get("error", {})
                            detail = (
                                str(error.get("message", ""))
                                + " "
                                + str(error.get("metadata", {}).get("raw", ""))
                            )
                            if self.key:
                                detail = detail.replace(self.key, "[REDACTED]")
                            error_reason += ":" + scrub(detail)[:2048]
                        except (ValueError, AttributeError, TypeError):
                            pass
                        raise ProviderFailure("provider_http_" + str(response.status_code))
            obj = json.loads(data)
            usage = obj["usage"]
            # Meter before validating content: malformed model JSON can still be billed.
            reply_data = dict(
                tokens_input=usage["prompt_tokens"],
                tokens_output=usage["completion_tokens"],
                cost_usd=usage.get("cost"),
                completion_id=obj.get("id"),
                provider_model=obj.get("model"),
                backend_provider=obj.get("provider"),
            )
            meter = ProviderReply.model_validate(reply_data)
            estimate = (
                meter.tokens_input * self.input_usd_per_million
                + meter.tokens_output * self.output_usd_per_million
            ) / 1_000_000
            cost = meter.cost_usd if meter.cost_usd is not None else estimate
            if self.ledger and reservation:
                self.ledger.settle(
                    reservation,
                    cost,
                    {
                        **reply_data,
                        "cost_basis": "provider_reported"
                        if meter.cost_usd is not None
                        else "token_estimate",
                    },
                )
                settled = True
            message = obj["choices"][0]["message"]
            raw = json.dumps(
                {k: message.get(k) for k in ("content", "tool_calls")}, ensure_ascii=False
            )
            try:
                calls = tuple(
                    ToolCall(
                        call_id=c["id"],
                        name=c["function"]["name"],
                        arguments=json.loads(c["function"]["arguments"]),
                    )
                    for c in message.get("tool_calls", [])
                )
            except (TypeError, KeyError, ValueError):
                return ProviderReply(
                    content=message.get("content") or "",
                    raw_output=raw,
                    error_code="invalid_tool_arguments",
                    **reply_data,
                )
            return ProviderReply(
                content=message.get("content") or "",
                raw_output=raw,
                tool_calls=calls,
                finish_reason=obj["choices"][0].get("finish_reason"),
                **reply_data,
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise ProviderFailure("provider_invalid_or_unavailable") from exc
        finally:
            if self.ledger and reservation and not settled:
                self.ledger.fail(reservation, error_reason)
