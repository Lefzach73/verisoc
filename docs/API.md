# Authenticated API v1

`docs/openapi.json` is generated from the actual app. Every data endpoint requires Bearer auth.
No X-Tenant-ID, model argument, URL or request body can confer tenant authority. Foreign/missing
records return concealed not_found. Health is minimal and public; OpenAPI shows schemas, not data.

Start a reviewed research instance explicitly on loopback:

```sh
# Configure VERISOC_DATABASE_URL and VERISOC_SIGNING_KEY (≥32 bytes) in server environment.
# PostgreSQL: run migrations as admin, connect only as a restricted non-owner role.
uv run --frozen --no-editable uvicorn verisoc.api.main:create_app --factory --host 127.0.0.1 --port 8000
```

SQLite additionally requires VERISOC_MODE=single-tenant-demo and is untrusted demo only.
No signing key is hardcoded. Tokens are issued by a trusted test/research issuer using HS256,
issuer verisoc-research, audience verisoc-api and exp/iat/nbf/sub/tenant_id UUID. Identity lifecycle,
OIDC deployment and key rotation are not implemented as a production service.

| Endpoint | Input/result |
|---|---|
| POST /v1/events/import | dataset_id + jsonl string → pinned import manifest |
| POST /v1/cases/detect | dataset_id → actual deterministic cases |
| GET /v1/cases | limit ≤100, offset → tenant-only cases |
| GET /v1/cases/{id} | scoped Case |
| POST /v1/cases/{id}/investigate | bounded mock-only safe report |
| GET /v1/cases/{id}/report | vetted report, evidence rechecked |
| GET /healthz | status and explicit research/demo mode |

Import request (ordinary input, no tenant marker/labels):

```json
{"dataset_id":"lab-sample","jsonl":"{\"event_code\":4688,\"timestamp\":\"2026-01-01T00:00:00Z\",\"process\":\"lab-indicator.exe\"}\n"}
```

Response contains tenant_id from token context, file SHA-256, accepted/duplicate counts and
actual stable event IDs. Unknown/malformed fields produce {"error":"invalid_request"}.
Invalid auth → 401; concealed foreign ID → 404; malformed input → 422; oversize → 413;
per-tenant expensive-operation budget → 429. Provider limits yield needs_review in report.

The in-memory limiter caps 30 expensive actions/minute/tenant; no distributed/public-service
rate-limiter guarantee. Backend has no arbitrary hosted-model invocation, async jobs, export
filesystem path input or controller. JSON clients must escape untrusted hypothesis text.
