# Internal implementation review — independent review pending

Reviewed code against master-spec boundaries during implementation, not an independent audit.
Concrete checks: authenticated issuer/audience/expiry/tenant context; concealed foreign IDs;
parameterized query paths; per-transaction context reset; every table FORCE RLS/non-owner role;
policy expressions and excess TRUNCATE/UPDATE/DELETE grants; predicate mismatch even for existing
citations; source/canonical tampering; neutral factual narrative; stored-report re-verification;
no label import into runtime; projected contexts; bounded model/tool output and failures; no
shell/SQL/URL/cloud tool; synthetic injection; immutable unique evaluation paths and fingerprints.

The optional dependency audit initially failed on diskcache. Removed that dependency via a
compatibility-tested older pySigma pin and constrained Sigma surface, retained the initial failure,
then reran the full advisory scan successfully. Source hygiene scanner checks bounded secret
patterns and excludes raw external data from tracked files. Dependency license inventory records
metadata, including unknown license fields; it does not fabricate clearance.

Not proven: production deployment, side-channel resistance, compromised DB owner/application
code/signing key, distributed rate limiting, provider billing accuracy/failure cost, model-level
prompt-injection generalization, raw-log truth, benignness from absence of a detector, independent
PI reviews or human annotations. The two-model synthetic pilot and ten inert adversarial cases completed; bounded results are in research/results/RESULTS.md. Actual GitHub CI passed on frozen v0.3 and its output-budget repair; run links are in IMPLEMENTATION_STATUS.md. Docker test service prepared, native PostgreSQL actually tested.

Release disposition: local engineering handoff acceptable within these assumptions; scientific
or production release blocked on independent review, licensed real data/annotations and G5.

## v0.2 follow-up

Regression checks reproduced same-tenant JSON substitution across event/case/report database keys,
forged report supporting IDs/narrative, duplicate JSON keys, numeric timestamp coercion and oversized
authentication witnesses before fixes. Storage now checks indexed and payload identities/time;
report reads reconstruct verified support and downgrade changed evidence. Dense rules use bounded
witnesses and timestamp batches, preserving strict chronology. The EVTX adapter rejects DTD/entity
expansion and ambiguous repeated fields, and never executes event contents. These internal checks
still do not substitute for independent security review.

## v0.3 executed checks

95 offline tests and 7 real PostgreSQL tests pass; 17,964 finite verifier/oracle checks found no
disagreement or counterfactual acceptance. Two five-case model adversarial runs observed no
unauthorized exposure or action, with one failed/rejected case per model. These are bounded
internal checks. Twelve external EVTX files were checked without execution; eleven yielded
57 admitted records. Full scientific and independent security acceptance remain separate.
