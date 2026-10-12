# VeriSOC

**Security triage that checks its claims against the evidence.**

VeriSOC is a Python research prototype for importing security events, detecting bounded patterns,
and verifying proposed observations against authorized source records. An untrusted model may
propose a claim; independent code decides whether the evidence supports it. Missing evidence
leads to a request for human review.

[Architecture](docs/ARCHITECTURE.md) · [CLI and API](docs/USAGE.md) ·
[Research boundaries](docs/RESEARCH_STATUS.md) · [Export provenance](docs/PUBLIC_EXPORT.md)

## Run the offline demo

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). Initial setup installs locked
dependencies. The demo, native baseline and tests then need no API keys or model services.

```sh
make setup
make demo
make test
make bench-smoke
```

The bundled fixture contains authored synthetic events for two tenants. The demo imports one
tenant's records, detects actual rule matches, accepts a supported observation, rejects an
unsupported process claim, and returns `needs_review`. Generated files stay under ignored
`artifacts/` directories. Repeated imports are idempotent.

## Evidence flow

```mermaid
flowchart LR
    A[Supported security events] --> B[Canonical records and source hashes]
    B --> C[Bounded detections]
    C --> D[Authorized read-only evidence]
    D --> E[Untrusted candidate claims]
    E --> F[Independent verification]
    F --> G[Verified observations and human review]
```

| Component | Implemented behavior |
| --- | --- |
| Ingestion | Validated JSONL, canonical events, content hashes, source lineage and duplicate detection. |
| Detection | Explicit count, event-order and process-image rules; limited optional Sigma and EVTX support. |
| Verification | Recomputes typed predicates, chronology, authorized scope and provenance. |
| Evidence selection | Bounded read-only tools and ID-only selection; final independent checks. |
| Context | Source-pinned approval and revocation records with exact event and tenant bindings. |
| Isolation | Validated JWT tenant context and PostgreSQL FORCE RLS; SQLite is a local demonstration mode. |
| Evaluation | Separate labels and raw-record oracles, matched mock baselines, immutable inputs and blank human-review forms. |

## Verify and explore

```sh
make lint                    # formatting, lint and strict type checking
make test-all                # includes optional Sigma and EVTX parsers
make workflow-demo           # freeze, blank review forms and matched offline mocks
make verify-export           # check copied source against the original snapshot
```

The complete original core test suite is retained. Tests cover tenant isolation, forged evidence,
tampered provenance, malformed provider responses, hostile log strings, budgets, review custody,
and evaluation leakage. [Local acceptance](docs/ACCEPTANCE.md) records the commands actually run.

PostgreSQL integration is separate and explicit: `make test-integration` creates a temporary local
PostgreSQL 17 cluster and removes it afterwards. CI uses a disposable PostgreSQL service and mock
providers; it contains no hosted-model credentials. See [reproduction](docs/REPRODUCE.md).

## Research status

This repository is a clean, runnable companion to a private research archive. It preserves the
original runtime, tests, synthetic fixtures and lockfile, with a new public history. The
[export manifest](PUBLIC_EXPORT_MANIFEST.json) identifies original hashes and every omitted file.
Private operator diagnostics and the full historical experiment archive are not bundled.

Earlier real-model experiments **did not establish the incident-recall noninferiority target**.
Later authored controls demonstrate software behavior, not independent production efficacy.
The public demo is marked `smoke_only`; no mock result is presented as LLM performance.
Independent incident labels, blinded human review and prospective confirmation remain outstanding.

VeriSOC performs defensive, read-only analysis. It does not execute log content, scan networks,
remediate incidents or manage infrastructure. Record hashes support integrity under stated
assumptions; they do not prove source authenticity or malicious intent. This is an experimental
implementation, not a production SOC or a security certification.

## Research context and attribution

The project is motivated by coauthored work on [shared SOCs for SMEs](https://doi.org/10.1007/978-3-031-95652-2_22)
and [LLMs in cyber defense](https://doi.org/10.1007/978-3-031-81322-1_5).
Those publications do not establish this implementation's efficacy.

Development used AI coding assistance. Repository ownership and commit attribution do not establish
sole scientific authorship, independent review or personal authorship of every implementation detail.
[Contribution policy](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Citation metadata](CITATION.cff)

Original code and synthetic fixtures are covered by the [MIT License](LICENSE). External data and
optional dependencies retain their own licenses. [License audit](docs/LICENSE_AUDIT.md).
