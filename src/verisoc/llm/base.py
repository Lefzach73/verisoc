from typing import Annotated, Any, Protocol

from pydantic import Field

from verisoc.core.models import Frozen


class Budget(Frozen):
    max_input_tokens: Annotated[int, Field(ge=1, le=65536, strict=True)] = 16384
    max_output_tokens: Annotated[int, Field(ge=1, le=8192, strict=True)] = 2048
    max_tool_calls: Annotated[int, Field(ge=0, le=8, strict=True)] = 8
    max_model_calls: Annotated[int, Field(ge=1, le=4, strict=True)] = 2
    max_seconds: Annotated[float, Field(gt=0, le=60, allow_inf_nan=False)] = 10
    max_usd: Annotated[float, Field(ge=0, le=100, allow_inf_nan=False)] = 0
    max_response_bytes: Annotated[int, Field(ge=1024, le=131072, strict=True)] = 65536


class ToolCall(Frozen):
    call_id: Annotated[str, Field(min_length=1, max_length=128)]
    name: Annotated[str, Field(min_length=1, max_length=64)]
    arguments: dict[str, Any]


class ProviderReply(Frozen):
    content: str = ""
    raw_output: str | None = None
    error_code: str | None = None
    tool_calls: Annotated[tuple[ToolCall, ...], Field(max_length=8)] = ()
    cost_usd: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None
    completion_id: Annotated[str, Field(max_length=256)] | None = None
    backend_provider: Annotated[str, Field(max_length=256)] | None = None
    provider_model: Annotated[str, Field(max_length=256)] | None = None
    finish_reason: Annotated[str, Field(max_length=64)] | None = None
    tokens_input: Annotated[int, Field(ge=0, strict=True)]
    tokens_output: Annotated[int, Field(ge=0, strict=True)]


class Provider(Protocol):
    provider_id: str
    model_id: str
    input_usd_per_million: float
    output_usd_per_million: float
    price_snapshot: str

    def input_upper_bound(
        self, messages: list[dict[str, Any]], budget: Budget, seed: int
    ) -> int: ...

    async def generate(
        self, messages: list[dict[str, Any]], budget: Budget, seed: int
    ) -> ProviderReply: ...
