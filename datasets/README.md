# Defensive dataset policy

Only original synthetic telemetry is bundled. `fixtures/demo` has 24 author-specified scenarios;
labels/expected supporting rows are evaluation-only. No customer data or payload is included.
OTRF is available as a public repository but its README GPL-3.0/LICENSE MIT discrepancy remains
unresolved for exact datasets. Nothing from OTRF was downloaded or redistributed.

Optional user-initiated path:

```
verisoc datasets audit-license --manifest datasets/external/example_manifest.yaml
# Example is intentionally pending and exits 2.
python scripts/prepare_external_dataset.py --manifest /path/to/approved.yaml \
  --out datasets/raw/audited-events.jsonl --accept-license
```

Audit requires exact source commit, SHA-256, license URL/SPDX, attribution, reviewer/date and
resolution evidence for discrepancies. User agreement is explicit. No archive extraction,
executable content or automatic downloads. JSONL must satisfy the documented v1 raw contract.
Fetch validates checksum/size, refuses redirects/overwrite; raw output belongs outside Git.
Do not edit the example into an approval without an actual documentary audit.
