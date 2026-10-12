# CLI and API

Start with `make demo` for a complete authored-data example. Individual commands are available
through `uv run --frozen --no-editable verisoc --help` and
`uv run --frozen --no-editable python -m verisoc.v05 --help`.

```sh
uv run --frozen --no-editable verisoc init --mode single-tenant-demo
uv run --frozen --no-editable verisoc datasets import \
  --input fixtures/demo/events.jsonl --tenant demo-a --fixture
uv run --frozen --no-editable verisoc cases detect --dataset demo --tenant demo-a
```

Use a detected case UUID in the following commands:

```sh
uv run --frozen --no-editable verisoc cases investigate --case-id UUID --provider mock
uv run --frozen --no-editable verisoc reports show --case-id UUID
```

The `--tenant` option is trusted local fixture selection, never service authorization. Real
API endpoints derive tenant identity from validated JWT context and use a restricted PostgreSQL
role. See [API contracts](API.md), [OpenAPI](openapi.json) and the [threat model](THREAT_MODEL.md).

The newer evidence path can open a bounded time window without requiring a legacy alert, derive
typed facts, select offered IDs and independently recheck the report. The v0.5 module adds
source-pinned approval context, intake validation, source freezes, blank review forms and scored
review custody. `make workflow-demo` exercises its local stages using authored controls only.

Inert prompt-injection text and suspicious process names are fixture strings. No source text is
executed. The model tool interface does not expose a shell, arbitrary SQL, tenant selection or
arbitrary network access. Optional real-provider adapters remain disabled unless explicitly
configured; they are not part of the default public workflow or CI.
