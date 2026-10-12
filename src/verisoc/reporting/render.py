import html
import unicodedata

from verisoc.core.models import InvestigationReport


def safe_text(value: str) -> str:
    return html.escape("".join(c for c in value if not unicodedata.category(c).startswith("C")))


def render(report: InvestigationReport) -> str:
    lines = [f"Verdict: {report.verdict}", "Verified observations (predicate facts only):"]
    for decision in report.verified_claims:
        # Never echo free-form model explanations as independently verified facts.
        lines.append(
            f"- {decision.candidate.claim_kind}: "
            + ", ".join(str(e) for e in decision.supporting_event_ids)
        )
    for hypothesis in report.hypotheses:
        lines.append("UNVERIFIED HYPOTHESIS: " + safe_text(hypothesis.explanation))
    if report.evidence_details:
        lines.append("Authorized record details:")
    for event in report.evidence_details:
        fields = event.model_dump(mode="json", exclude_none=True)
        summary = " | ".join(
            f"{k}={fields[k]}"
            for k in ("host_id", "user_id", "process_name", "dst_port")
            if k in fields
        )
        lines.append(
            safe_text(
                f"- {event.event_id} | {event.occurred_at.isoformat()} | "
                f"{event.source_kind}/{event.outcome} | {summary}"
            )
        )
        lines.append(
            f"  Source SHA256 {event.source_ref.file_sha256}, row {event.source_ref.row_index}; "
            f"canonical SHA256 {event.canonical_sha256}"
        )
    lines.append("Limitations: " + ", ".join(report.missing_evidence + report.limit_reasons))
    lines.append("Record hashes do not establish source authenticity or malicious intent.")
    return "\n".join(lines)
