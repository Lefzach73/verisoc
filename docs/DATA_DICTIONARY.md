# Data contracts and mappings

See docs/contracts for generated JSON Schema and docs/openapi.json for the real API contract.
Supported input is one explicit `verisoc-jsonl-v1` JSON object per line. Extra fields are rejected.

| Raw field | Canonical meaning | Validation |
|---|---|---|
| event_code 4624 / 4625 | Windows authentication login success / failure | Supported literal only |
| event_code 4688 | Windows process start, outcome success | process may be missing |
| event_code 3 | Small laboratory network connection contract | Not a full Sysmon export/parser |
| timestamp | occurred_at | Timezone required; normalized UTC |
| host / user | host_id / user_id | Tenant-salted SHA-256 pseudonyms, 24 hex chars |
| process | process_name | Bounded text, scrubbed secrets/emails |
| src_ip / dst_ip | IP addresses | IPv4/IPv6 validation; omitted from model projection |
| src_port / dst_port | Ports | Strict integers, 0–65535 |
| message | attributes.message | ≤2048 chars, secrets/email/control scrub; omitted from prompts |

This is a small normalized export format, not direct EVTX/XML or all Windows event fields.
`fixture_tenant` exists only in bundled local synthetic import with --fixture; API imports reject it.
No gold verdict/family/rationale is accepted by RawEvent or stored in runtime tables.

File bytes SHA-256 pin a tenant/dataset name. Source row has one-based index and validated-raw-row
JSON hash. Stable UUID5 uses tenant, dataset, file hash, row offset and raw-row hash. Semantic exact
duplicate deliveries within a file are counted and skipped; first row retains lineage. Reimport
of same bytes returns existing IDs; changed bytes under the same tenant/dataset cause conflict.
Malformed imports roll back atomically; all rows are validated before writes.

Canonical hash uses sorted compact normalized JSON excluding canonical_sha256 and ingested_at
(the latter is operational admission time, not evidence identity). Source hashes, stored source
row and typed predicate are checked independently on every verification. Equal timestamps do
not prove temporal_order. Null shared host/user yields insufficient. Hashes cannot prove log truth.
