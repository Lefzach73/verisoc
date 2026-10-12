# Reproduction

Python 3.12 and uv are required; development used Python 3.12.13 and uv 0.11.8. Run from the
repository root. `make setup` installs the pinned environment from `uv.lock`. Subsequent demo,
native mock benchmark and tests run offline with `UV_OFFLINE=1` after dependencies are installed.
`make test-all` additionally installs the locked optional parsers and plotting library.

```sh
make setup
make lint
make test
make test-all
make demo
make bench-smoke
make workflow-demo
make verify-export
```

Make uses source `PYTHONPATH` and a non-editable installed wheel. To check the installed package
without that source override, run:

```sh
env -u PYTHONPATH UV_OFFLINE=1 uv run --frozen --no-editable --all-extras pytest -m 'not postgres'
```

The demo writes SQLite under `artifacts/demo`. Mock evaluation creates a new run directory with
hashes, configuration, predictions and `research_validity=smoke_only`. It never calls a model.
`workflow-demo` creates a fresh authored-data intake, source freeze, blank unassigned-reviewer
forms and matched mock arms. It does not create genuine human judgments or independent gold.
All runtime output is ignored by Git. Do not publish arbitrary logs without inspecting them.

## PostgreSQL integration

Real row-level security tests are opt-in locally. Install PostgreSQL 17 binaries and run:

```sh
VERISOC_PG_BIN=/path/to/postgresql/bin make test-integration
```

The supplied runner creates a temporary synthetic cluster on loopback, creates a restricted
application role, tests RLS, and stops/removes the cluster in cleanup. No persistent service is
required. If explicit database URLs are set, they must point to a disposable test database.
CI uses the pinned PostgreSQL 17 container from the original validated workflow with synthetic
test-only passwords; it does not connect to production.

## Optional source adapters

Native EVTX conversion requires `uv run --frozen --no-editable --extra evtx verisoc datasets
convert-evtx --help`. The supported Windows event subset is narrow and unsupported events are
reported explicitly. Source-license audits and bounded external preparation scripts remain
available; no external dataset is fetched by setup, tests or the demo.

The preserved historical aggregation scripts require original study archives, which are not
bundled here. Their tamper-detection unit tests still run using temporary synthetic inputs. The
public export's own checks do not pretend to revalidate absent private study artifacts.
