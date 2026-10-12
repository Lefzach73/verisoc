# Threat model v1

Adversary controls strings and candidate model outputs, forged UUID citations, tool arguments,
tenant headers, malformed imports and request volume. Records may contain inert injection text.
Adversary does not control server signing keys, application code, DB owner or the trusted import
context. A compromised DB owner can rewrite content and matching hashes; hashes are identity
and tamper-detection checks under this assumption, not authenticity proofs.

Trusted: server token validation, tenant-scoped repository, FORCE RLS with a non-owner role,
normalizer, deterministic detector, verifier and policy. Untrusted: source data, model, retrieved
text and explanations. No model tool executes code, arbitrary SQL/HTTP or state-changing actions.

Fail closed: missing tenant context; invalid token issuer/audience/expiry; foreign/missing IDs
share concealed errors; missing/inconsistent evidence or provider failure → needs_review.
Every query/export is scoped. No cross-request context cache or asynchronous job system exists.
Bound imports, events, tool calls, returned text, model bytes, tokens, cost and deadlines.
Only minimized pseudonymized fields may leave the process with explicit model opt-in.

SQLite is a local engineering demo with application filtering, not a secure multi-tenant DB.
Authenticated research mode refuses SQLite and owner/BYPASSRLS/superuser PostgreSQL connections.
Security tests cover evaluated scenarios only. Timing side channels, malicious privileged
operators, advanced provider behavior, deployment/network hardening and production identity
lifecycle require independent review. Prototype unsuitable for production SOC deployment.
