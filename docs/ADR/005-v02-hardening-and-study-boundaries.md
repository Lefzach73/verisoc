# ADR 005: Preserve frozen research results across v0.2 hardening

Status: accepted for this local implementation; independent review pending.

The real-model synthetic pilot used clean commit 526cd5deb75e918812d02490032f6017be57336d,
native rules 1.0 and prompt candidate-1.3. Preserve that source and every original artifact,
including failures. v0.2 introduces identity-bound database reads, repeated report-verdict policy
checks, strict import parsing, bounded native-1.1 detection and optional EVTX conversion.
These engineering changes do not retroactively alter the study or establish new model efficacy.

Dense detections reference at most 32 actual failures plus one success. Equal-time events are
processed in a batch, so UUID/arrival order cannot manufacture strict chronology. Witness counts
are not total event counts. Existing raw events remain available in the authorized dataset.

A public four-event EVTX file was used only for format interoperability and remains outside the
release. It has no independent case-level truth and does not satisfy the external-shift study gate.

Offline aggregation validates exact 384-observation pairing and original checksums before reporting
all arms, failures and family-bootstrap intervals. B3 verdict coverage is zero for both models;
claim-contract rejection rates must not be labeled hallucination rates. Independent annotations,
security review, PI acceptance and a representative external study remain research-release gates.
