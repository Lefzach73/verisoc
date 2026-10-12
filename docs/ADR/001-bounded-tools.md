# ADR 001 — Bounded read-only investigation

Accepted for implementation 2026-10-11; PI review pending. Use a fixed typed tool registry,
parameterized repository calls, per-case dataset/time scope, row/text/call caps and no shell,
arbitrary SQL, URL fetching, remediation or cloud privileges. Tool output is data, never
instructions. Sacrifices unrestricted hunting to make authorization and budgets testable.
