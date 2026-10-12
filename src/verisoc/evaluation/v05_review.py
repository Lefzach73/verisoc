"""Offline blinded review artifacts; preparing forms never counts as submitted human judgments."""

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from verisoc.core.ids import stable_id
from verisoc.core.models import Digest, Frozen, Text, utc
from verisoc.core.provenance import digest, json_hash
from verisoc.evaluation.oracle import RawRecordOracle
from verisoc.evaluation.v05_context_inputs import context_bundles, visible_context
from verisoc.evaluation.v05_intake import IntakeManifest, read_events
from verisoc.evaluation.v05_study import freeze_identity, json_bytes, verify_study, write_new


class SubmittedReview(Frozen):
    blinded_case_id: Text
    reviewer_id: Text
    packet_sha256: Digest
    label: Literal["malicious", "benign", "needs_review"]
    rationale: Annotated[str, Field(min_length=20, max_length=4000)]
    cited_event_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=500)]
    blind_to_outputs: Literal[True]
    independent_of_authors: Literal[True]
    human_attestation_reference: Text
    submitted_at: datetime

    _utc = field_validator("submitted_at")(utc)


class SubmittedAdjudication(Frozen):
    adjudicator_id: Text
    label: Literal["malicious", "benign", "needs_review"]
    packet_sha256: Digest
    review_pair_sha256: Digest
    rationale: Annotated[str, Field(min_length=20, max_length=4000)]
    cited_event_ids: Annotated[tuple[str, ...], Field(min_length=1, max_length=500)]
    human_attestation_reference: Text
    submitted_at: datetime

    _utc = field_validator("submitted_at")(utc)


def packet_evidence_ids(packet: dict[str, Any]) -> set[str]:
    return {e["event_id"] for e in packet["evidence"]} | {
        c["context_id"] for c in packet.get("recorded_context", [])
    }


def review_pair_hash(reviews: list[dict[str, Any]]) -> str:
    return json_hash(sorted(reviews, key=lambda r: r["reviewer_id"]))


def check_review_bundle(forms: Path) -> None:
    record = forms / "review-manifest.json"
    if not record.exists():
        mapping = json.loads((forms / "custodian-mapping.json").read_text())
        if mapping.get("schema_version") == "review-forms-1.1":
            raise ValueError("Missing review artifact manifest")
        return  # Historical 1.0 format remains readable, with human validity unverified.
    manifest = json.loads(record.read_text())
    required = {
        "custodian-mapping.json",
        "blind-packets.json",
        "reviewer-1.html",
        "reviewer-2.html",
    }
    if set(manifest["file_sha256"]) != required:
        raise ValueError("Incomplete review artifact inventory")
    for name, expected in manifest["file_sha256"].items():
        path = forms / name
        if path.is_symlink() or digest(path.read_bytes()) != expected:
            raise ValueError("Review artifact changed")


def export_blind_forms(study: Path, reviewer_ids: tuple[str, str], out: Path) -> dict[str, Any]:
    verify_study(study)
    intake = IntakeManifest.model_validate_json((study / "intake.json").read_text())
    if len(set(reviewer_ids)) != 2 or any(
        r in {c.author_id for c in intake.cases} for r in reviewer_ids
    ):
        raise ValueError("Two distinct reviewers independent of case authors required")
    validation = json.loads((study / "validation.json").read_text())
    details = {c["case_id"]: c for c in validation["cases"]}
    packets = []
    mapping = {}
    for case in intake.cases:
        blinded = str(stable_id("blind-case", freeze_identity(study), case.case_id))
        mapping[blinded] = dict(case_id=case.case_id, author_id=case.author_id)
        raw = read_events((study / "inputs" / case.event_file).read_bytes())
        evidence = []
        for index, eid in zip(case.row_indexes, details[case.case_id]["event_ids"], strict=True):
            event = raw[index - 1]
            fields = event.model_dump(mode="json", exclude={"message"})
            fields["host"] = RawRecordOracle.identity(event.host, case.tenant_id)
            fields["user"] = RawRecordOracle.identity(event.user, case.tenant_id)
            evidence.append(dict(event_id=eid, source_row=index, fields=fields))
        context = [
            r
            for bundle in context_bundles(study / "inputs", intake, case)
            for r in visible_context(bundle, {UUID(e["event_id"]) for e in evidence})
        ]
        for record in context:
            record["context_id"] = "context-" + json_hash(record)
        packets.append(dict(blinded_case_id=blinded, evidence=evidence, recorded_context=context))
    payload = json_bytes(packets)
    packet_hash = digest(payload)
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    write_new(
        out / "custodian-mapping.json",
        json_bytes(
            dict(
                schema_version="review-forms-1.1",
                issued_at=datetime.now(UTC).isoformat(),
                mapping=mapping,
                reviewer_ids=reviewer_ids,
                packet_sha256=packet_hash,
                study_manifest_sha256=freeze_identity(study),
            )
        ),
    )
    write_new(out / "blind-packets.json", payload)
    for number, reviewer in enumerate(reviewer_ids, 1):
        data = base64.b64encode(
            json_bytes(dict(reviewer_id=reviewer, packet_sha256=packet_hash, packets=packets))
        ).decode()
        # The packaged template exposes raw rows through a collapsible evidence section.
        document = Path(__file__).with_suffix(".html").read_text().replace("PAYLOAD", data)
        write_new(out / f"reviewer-{number}.html", document.encode())
    write_new(
        out / "review-manifest.json",
        json_bytes(
            dict(
                schema_version="review-manifest-1.0",
                file_sha256={p.name: digest(p.read_bytes()) for p in out.iterdir() if p.is_file()},
            )
        ),
    )
    return dict(
        forms=2,
        cases=len(packets),
        packet_sha256=packet_hash,
        submitted_human_reviews=0,
        human_authenticity_verified=False,
    )


def validate_submissions(
    forms: Path,
    reviews: tuple[SubmittedReview, ...],
    adjudications: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    check_review_bundle(forms)
    mapping = json.loads((forms / "custodian-mapping.json").read_text())
    content = (forms / "blind-packets.json").read_bytes()
    if digest(content) != mapping["packet_sha256"]:
        raise ValueError("Blind packet changed")
    packets = {p["blinded_case_id"]: p for p in json.loads(content)}
    grouped: dict[str, dict[str, SubmittedReview]] = {}
    issued = datetime.fromisoformat(mapping["issued_at"])
    for r in reviews:
        if not issued <= r.submitted_at <= datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("Review must follow packet issuance and not be future dated")
        if (
            r.blinded_case_id not in packets
            or r.reviewer_id not in mapping["reviewer_ids"]
            or r.packet_sha256 != mapping["packet_sha256"]
            or r.reviewer_id == mapping["mapping"][r.blinded_case_id]["author_id"]
        ):
            raise ValueError("Unknown reviewer/case, packet mismatch or self-review")
        allowed = packet_evidence_ids(packets[r.blinded_case_id])
        if len(set(r.cited_event_ids)) != len(r.cited_event_ids):
            raise ValueError("Duplicate review citation")
        if not set(r.cited_event_ids) <= allowed:
            raise ValueError("Review cites unavailable evidence")
        group = grouped.setdefault(r.blinded_case_id, {})
        if r.reviewer_id in group:
            raise ValueError("Duplicate reviewer")
        group[r.reviewer_id] = r
    labels: dict[str, str] = {}
    conflicts = []
    for cid in packets:
        pair = grouped.get(cid, {})
        if len(pair) != 2:
            raise ValueError("Two actual submitted reviews required for every case")
        values = {r.label for r in pair.values()}
        if len(values) == 1:
            labels[cid] = next(iter(values))
        else:
            conflicts.append(cid)
    decisions = adjudications or {}
    if not set(decisions) <= set(conflicts):
        raise ValueError("Adjudication of unknown/nonconflicting case")
    for cid in conflicts:
        a = decisions.get(cid)
        if not a:
            continue
        if (
            a.get("adjudicator_id")
            in {*mapping["reviewer_ids"], mapping["mapping"][cid]["author_id"]}
            or not a.get("adjudicator_id")
            or a.get("label") not in ("malicious", "benign", "needs_review")
            or len(a.get("rationale", "")) < 20
            or not a.get("human_attestation_reference")
        ):
            raise ValueError("Independent documented adjudication required")
        if mapping.get("schema_version") == "review-forms-1.1":
            decision = SubmittedAdjudication.model_validate(a)
            originals = [r.model_dump(mode="json") for r in grouped[cid].values()]
            if decision.packet_sha256 != mapping["packet_sha256"] or (
                decision.review_pair_sha256 != review_pair_hash(originals)
            ):
                raise ValueError("Adjudication belongs to different evidence or original judgments")
            if not set(decision.cited_event_ids) <= packet_evidence_ids(packets[cid]):
                raise ValueError("Adjudication cites unavailable evidence")
            if len(set(decision.cited_event_ids)) != len(decision.cited_event_ids):
                raise ValueError("Duplicate adjudication citation")
            if (
                not max(r.submitted_at for r in grouped[cid].values())
                <= decision.submitted_at
                <= (datetime.now(UTC) + timedelta(minutes=5))
            ):
                raise ValueError("Adjudication must follow both original judgments")
        labels[cid] = a["label"]
    return dict(
        structural_status="PASS" if len(labels) == len(packets) else "BLOCKED",
        unresolved_disagreements=[c for c in conflicts if c not in labels],
        adjudicated_labels=labels,
        original_reviews=[r.model_dump(mode="json") for r in reviews],
        adjudications=decisions,
        raw_agreement=sum(len({r.label for r in pair.values()}) == 1 for pair in grouped.values())
        / len(packets),
        reviewed_benign_cases=sum(label == "benign" for label in labels.values()),
        human_authenticity_verified=False,
        scientific_status="BLOCKED pending independent custodian verification of human submissions",
    )


def adjudication_template(forms: Path, review_result: dict[str, Any], out: Path) -> None:
    """Executable third-reviewer form, with evidence and both original judgments."""
    check_review_bundle(forms)
    packets = {
        p["blinded_case_id"]: p for p in json.loads((forms / "blind-packets.json").read_text())
    }
    mapping = json.loads((forms / "custodian-mapping.json").read_text())
    cases = []
    for cid in review_result["unresolved_disagreements"]:
        originals = [r for r in review_result["original_reviews"] if r["blinded_case_id"] == cid]
        cases.append(
            dict(
                **packets[cid],
                original_reviews=originals,
                review_pair_sha256=review_pair_hash(originals),
            )
        )
    data = base64.b64encode(
        json_bytes(dict(packet_sha256=mapping["packet_sha256"], cases=cases))
    ).decode()
    template = Path(__file__).with_name("v05_adjudication.html").read_text()
    write_new(out, template.replace("PAYLOAD", data).encode())
