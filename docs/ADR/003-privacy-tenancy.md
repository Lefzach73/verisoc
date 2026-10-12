# ADR 003 — Privacy and tenancy

Accepted for implementation 2026-10-11; PI review pending. Use SQLite only for local demo and
evaluation. Real service requires PostgreSQL FORCE RLS, restricted non-owner connection,
transaction-local authenticated tenant identity and application filtering. Pseudonymize IDs,
scrub secrets, omit arbitrary source text from external model contexts. Gold lives only in
evaluation files, outside runtime tables. No tenant-selected header confers authorization.
