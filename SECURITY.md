# Security policy

VeriSOC is an experimental read-only research prototype. See the [threat model](docs/THREAT_MODEL.md)
and [architecture](docs/ARCHITECTURE.md) for trust assumptions. SQLite is an untrusted single-tenant
demo; authenticated tenancy requires a restricted PostgreSQL role with FORCE RLS and validated JWTs.

For a suspected vulnerability, prepare a minimal synthetic reproduction and contact the repository
owner through an established private channel. Do not include real telemetry or credentials in a
public issue. No monitored response-time guarantee or security mailbox is claimed.

The system cannot protect against a compromised trusted operator, arbitrary application-code
execution or a privileged database owner. Record hashes do not establish log authenticity or
malicious intent. Passing tests are evidence for evaluated boundaries, not a universal safety proof.
