# Public companion acceptance

Local verification on 12 October 2026: macOS arm64, Python 3.12.13, uv 0.11.8.
Source snapshot: `ddb618df1f6abff365638e55dd6660b206b9c700`.

| Command | Actual result |
| --- | --- |
| `UV_CACHE_DIR=.cache/uv uv sync --frozen --no-editable --all-extras` | Installed 79 pinned packages and the non-editable package. Only public package installation required network access. |
| `UV_CACHE_DIR=.cache/uv UV_OFFLINE=1 UV_NO_SYNC=1 make lint` | Ruff format/check passed; strict MyPy passed for 78 source modules. |
| `UV_CACHE_DIR=.cache/uv UV_OFFLINE=1 UV_NO_SYNC=1 make test-all` | Final run: 274 passed, 11 PostgreSQL tests deselected, 30.06 seconds. |
| `UV_CACHE_DIR=.cache/uv UV_OFFLINE=1 UV_NO_SYNC=1 make demo` | 236 unique records, 4 duplicates, 10 deterministic alerts; supported observation retained, unsupported process claim rejected, `needs_review`. |
| `UV_CACHE_DIR=.cache/uv UV_OFFLINE=1 UV_NO_SYNC=1 make bench-smoke` | 192 case/arm rows; summary explicitly `smoke_only`. |
| `UV_CACHE_DIR=.cache/uv UV_OFFLINE=1 UV_NO_SYNC=1 make workflow-demo WORKFLOW_DIR=artifacts/runs/public-acceptance-workflow` | Four authored DEV cases, 20 arm rows, zero pipeline failures; blank forms and `AWAITING_HUMAN_REVIEWS`. Scientific status remains blocked. |
| Installed package comparison with `PYTHONPATH` unset | All 80 Python/HTML assets matched source exactly, package version 0.4.0. |

The first export test run had 272 passes and two failures because the intentionally unapproved
example license manifest had been omitted. Restoring that original fixture and its dataset policy
resolved both failures; the full suite was rerun. No test, runtime behavior or license guard was
weakened. The inherited Starlette TestClient/httpx deprecation warning remains visible.

All 37 original test files are retained, including the 11 real PostgreSQL integration tests.
Those tests were not rerun locally for this documentation/export task. The public CI recipe
includes them against the original pinned disposable PostgreSQL service. A successful local
offline run does not substitute for a future remote CI result.

Source/output hashes are checked by `make verify-export`. The complete public-file inventory
includes original and newly authored files; after Git initialization it also requires an exact
match with tracked paths. The manifest itself is excluded from its own hash to avoid a circular
digest. Repository initialization, publication and remote CI are separate delivery steps.

No paid model call, raw external-data acquisition, cloud deployment or persistent service occurred.
The locally generated workflow records contain operator paths and stay ignored. Only sanitized
aggregate facts are documented here. Tests verify the implementation in evaluated conditions;
they do not establish detection efficacy, production readiness or independent scientific review.
