# License audit

Audit date 2026-10-11. Original code and synthetic fixtures are MIT; original ownership is subject
to PI review before publication. No university/customer code or upstream rule content was imported. A small public EVTX file was
used outside the repository for interoperability only; see the follow-up below. Dependency metadata
and full lock inventory are recorded in DEPENDENCY_LICENSES.json and uv.lock.

[OTRF README](https://github.com/OTRF/Security-Datasets/blob/master/README.md) retrieved during
G0 has a GPL-3.0 heading, while its [LICENSE](https://github.com/OTRF/Security-Datasets/blob/master/LICENSE)
contains MIT. This is an unresolved exact-file/revision licensing discrepancy. No OTRF raw
data will be downloaded or redistributed here. Audit must identify pinned commit, per-file
license, attribution, checksum, reviewer decision and documentary resolution of ambiguity.
Maintainer contact has not been made and must not be invented.

SOCBench and Sigma/pySigma are references, not vendored dependencies or benchmark results.
No trademark clearance is claimed. Audit commands and dependency versions belong in the status
log. Dataset audit status must be approved explicitly before optional user-initiated fetch.

## Optional Sigma compatibility snapshot

Installed and exercised official `pysigma==2.0.1` on 2026-10-11. Wheel metadata reports
`LGPL-2.1-only`. It is an optional dependency (`sigma` extra), not copied into this repository;
original config/rules/lab-process.sigma.yml is MIT. See dependency-license inventory for all
installed packages. Distribution/modification of the library must preserve its applicable
license/source obligations. No statement of universal legal clearance is made.

Compatibility test parses SigmaCollection.from_yaml, checks condition=`selection`, one exact
scalar process_name selection, no modifiers/wildcards, Windows process_creation only. Rejects
unsupported semantics explicitly. Native rules run by default. No full Sigma support claim.

## Final dependency decision (supersedes the initial pySigma version)

The first pip-audit found DiskCache 5.6.3's pickle/cache-directory-write advisory
PYSEC-2026-2447 / CVE-2025-69872 (reported twice for the same advisory). Initial JSON retained
as dependency-audit-initial.json. There was no listed fixed diskcache version.
Inspected PyPI metadata for pySigma 1.x and 0.11.23: 0.11.23 does not depend on diskcache.
Final optional pin is `pysigma==0.11.23`, validated by the same real compatibility tests;
`uv sync --all-extras` removed diskcache, its stubs, jq and RE2 from the final environment.
The old parser is confined to exact scalar equality, no modifiers/regex, no aliases/anchors,
no external features/pipelines/template metadata. This bounded compatibility choice is not
an endorsement of arbitrary older-parser input. Final full installed-environment pip-audit
completed with no known vulnerabilities. Scan snapshots are bounded by advisory database/date,
not universal safety or legal clearance. Final license inventory comes from installed wheels.

## v0.2 optional EVTX and external interoperability

Optional `python-evtx==0.8.1`, `defusedxml==0.7.1` and transitive hexdump metadata are recorded
in the refreshed installed-wheel inventory. The public Windows sample audit pins source commit,
license/source hashes and scope in research/external-interop.json. The repository README and
GPL-3.0 file agree, but no independent legal review is claimed. Original and derived external data
and license copy remain outside the repository/archive. No OTRF licensing ambiguity was resolved
by using this separate source. The v0.2 advisory scan found no known dependency vulnerabilities;
the unpublished local verisoc package is explicitly skipped by the PyPI advisory database.
