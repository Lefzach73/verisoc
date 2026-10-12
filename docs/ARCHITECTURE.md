# Architecture

Modular Python monolith: trusted importer → immutable canonical events/source lineage → scoped
repository → native deterministic alerts/cases → read-only projected evidence → candidate
provider → independent predicates/provenance → conservative report. Separate evaluator reads
gold files and stores predictions/metrics; runtime modules cannot import evaluation labels.

Pydantic frozen contracts forbid unknown fields, validate typed arguments, UTC timestamps, IPs
and sizes. Candidates cannot deserialize verification decisions. Internal verifier capability
marks provenance/predicate decisions; it is a code boundary, not protection from arbitrary Python
execution by a compromised operator. Reports replace candidate factual explanations with generated
neutral observations and recheck stored evidence before export. Inference stays unverified.

SQLAlchemy Core has six tenant-owned tables, composite tenant primary keys and no cross-tenant
unique constraints. Cases embed alerts, reports embed decisions, audit stores minimal verifier
metadata. No embedding store, background queue/job or metric service exists. Every operation
uses a transaction with server-authenticated tenant identity. PostgreSQL policy/grant readiness
checks refuse ownership/bypass, missing FORCE, permissive policies and excess evidence write grants.

API validates locally issued signed HS256 JWTs with fixed issuer/audience and required expiry,
issued-at, not-before, subject and tenant. Signing key comes from server environment (≥32 bytes),
never an untrusted header or body. This is a research token issuer contract, not a deployed OIDC
identity lifecycle. Default server binding in docs is loopback. Model endpoint is never selected
by an API caller; hosted models exist only in explicit evaluator configuration.

Budget preflight bounds full serialized adapter payload by UTF-8 bytes, reserves worst-case
configured output cost, checks actual cumulative usage, model/tool calls, output size/depth and
overall async deadline. No retries/redirects/proxy inheritance. Missing usage and provider errors
fail as needs_review; unknown billing on failures is documented. Selection prioritizes alert IDs.

Versioned SQL migration replaces Alembic for this small schema (ADR004). Native v1 rules are
not full Sigma; optional official pySigma validates a single exact-match process subset. Internal
schema is OCSF-inspired, not OCSF compliant. No ATT&CK corpus/IDs are fabricated.

## Versioned evidence and context paths

The additive evidence path derives typed facts within a bounded case window, offers at most
32 facts / 32 KiB per packet, accepts only offered fact IDs and independently recomputes the final
selection. Its bounded in-memory cache is keyed by tenant, case and complete input hashes; cached
candidates are reverified. It does not confer additional authority on a model.

The v0.5 path adds an independently checked context source for approvals and revocations. Context
records bind authority, tenant, dataset, exact event identities, canonical hashes and time windows.
Only trusted server configuration supplies authority pins. The authenticated route is provided by
`verisoc.v05.api.create_app(db, auth, context_sources)`; callers cannot add their own authority or
tenant fields. The response retains observations, indicators, verified context, unexplained flags
and the separate incident verdict. Source-backed approval context is still an assertion under a
trusted-custodian assumption, not proof of benign intent.

## Research orchestration

The explicit local workflow validates intake and contamination constraints, archives actual
source/input bytes, produces blank reviewer forms, and runs matched mock arms. Submission and
adjudication validation are separate later stages. It checks custody and schema constraints,
but cannot authenticate a human reviewer's identity by itself. It never fills judgments, starts
a scheduler or calls a paid model. Runtime evidence tools cannot access evaluation labels.

The public package version remains `0.4.0`, preserving the original source and dependency lock.
The additive `v05` module and API describe development interfaces; a public export does not
silently turn those into a new scientifically validated release.
