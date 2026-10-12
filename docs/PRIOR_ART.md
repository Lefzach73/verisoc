# Prior art audit

Retrieved 2026-10-11 (client date). Primary-source pages were opened and inspected during G0.
Descriptions are scoped to those sources; no replicated leaderboard results are claimed.

| Source | Observed capability / limitation | VeriSOC comparison |
|---|---|---|
| [SOCBench](https://github.com/DeepTempo/socbench) | Bounded NetFlow investigations, scoped read-only tools, budget caps, mock smoke, model arms; its unit/scoring differ. | Claim predicates and tenant-isolation evaluation; no direct SOCBench comparison. |
| [Cyber Defense Benchmark v3](https://arxiv.org/abs/2604.19533v3) | Open-ended Windows-event hunting, OTRF-based campaigns and Sigma-derived gold. Reports poor recall under its particular protocol. | Alert-triggered constrained triage; independent annotations required to avoid circular gold. |
| [SecRespond](https://arxiv.org/abs/2607.26791) | Post-compromise disk forensics and remediation planning across cyber ranges. | Read-only event triage has a narrower evidentiary scope; no full-forensics claim. |
| [Sigma specification](https://github.com/SigmaHQ/sigma-specification), [rules](https://github.com/SigmaHQ/sigma) | Vendor-neutral declarative detections; full condition/modifier semantics matter. | Hand-reviewed native rules initially. No full Sigma compatibility or bundled upstream rules. |
| [pySigma](https://github.com/SigmaHQ/pySigma) | Official Python parsing/conversion library. Exact package API and upstream licensing need validation. | Optional integration may follow compatibility tests; no homemade full parser. |
| [OCSF](https://github.com/ocsf/ocsf-schema) | Versioned event semantics/schema. | Internal v1 is OCSF-inspired only, not validated OCSF compliance. |
| [ATT&CK versions](https://attack.mitre.org/resources/versions/) | Retrieved page lists v19.2 as current. | Optional rule-authored IDs only; no model-generated taxonomy. |
| [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) | Covers prompt injection and disclosure risks. | All text/model output untrusted; code allowlists and isolation form the boundary. |
| [NIST GenAI profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence) | Risk management guidance for generative AI. | Explicit uncertainty, bounded evaluations and failure recording; no certification claim. |

The two coauthored publications linked from the README motivate this research. They have not been
independently replicated here. Full systematic literature review and human assessment remain open.

## Post-v0.3 targeted literature follow-up

The private research archive contains a subsequent literature-guided diagnosis and finite gate
audit following the failed recall-retention result. Those historical study artifacts are not
bundled in this public source companion. They do not establish successful efficacy or novelty;
see the public [research-status summary](RESEARCH_STATUS.md) and [export boundary](PUBLIC_EXPORT.md).
