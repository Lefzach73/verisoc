# ADR 004 — Gate prerequisites and reviewed SQL migration

Accepted 2026-10-11; PI review pending. G2 invariant 8 needs provider budgets and invariant 15
needs a runnable evaluator. Those G3 components were implemented as G2 prerequisites; G3 was
certified only after G2 tests passed. This resolves the master spec's cross-gate dependency.

Use SQLAlchemy Core with one explicit versioned SQL migration instead of Alembic's dynamic
migration runner. The small v1 schema has six tenant-owned tables; cases embed alerts, reports
embed decisions, source records preserve lineage, and audit records capture verification. No
cache/export/job table exists; report JSON is the scoped export. New persisted entities must
add tenant UUID and FORCE RLS tests. No live schema mutation by the application role.

The SQLite demo uses application isolation only. PostgreSQL startup checks role, table owner
privileges, RLS/FORCE and policy count. DB owner/code compromise remains outside the threat
model. The local test runner starts a loopback temporary instance and always shuts it down.
No service/controller or cloud lifecycle code is part of the runtime.
