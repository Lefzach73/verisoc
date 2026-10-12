# Bundled synthetic fixtures

All bundled records are authored synthetic controls under the original MIT license. Suspicious
process names and injection phrases are inert strings; no payloads or real customer logs are
included. Intent labels are stipulated simulation labels, not independently human-adjudicated truth.

| Fixture | Source event rows | Authored cases | Purpose |
| --- | ---: | ---: | --- |
| `demo` | 480 | 24 | Two tenants, deterministic alerts, duplicate deliveries and claim verification. |
| `output-regression` | 480 | 12 | Bounded provider-output regression controls. |
| `v03` | 3,048 | 120 | Original constructed corpus, retained with fixed split and evidence files. |
| `v04-dev` | 198 | 40 | Bounded evidence/correlation controls and benign lookalikes. |
| `v05-dev` | 122 | 24 | Source-pinned context controls; 14 additional context rows. |

Source rows can include duplicates, and are not counts of independent incidents. Labels and
expected-evidence files belong to the separate evaluator and cannot be retrieved by runtime
evidence tools. Historical development data remain marked as inspected; renaming a case does
not make it a new holdout. The contamination inventory is an incomplete screening aid, not
proof of independence.

External data are not bundled. Optional preparation requires exact source/license metadata and
explicit agreement. The intentionally pending example manifest must continue to fail its license
gate. See [dataset policy](../datasets/README.md) and [license audit](LICENSE_AUDIT.md).
