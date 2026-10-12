"""Structural gate for prospective human review; attestations are not identity proof."""

from typing import Annotated, Literal

from pydantic import Field

from verisoc.core.models import Digest, Frozen, Text


class ProspectiveCase(Frozen):
    case_id: Text
    family_id: Text
    author_id: Text
    source_sha256: Digest
    source_event_ids: Annotated[tuple[Text, ...], Field(min_length=1, max_length=500)]
    permission_reference: Text
    partition: Literal["development", "holdout"]


class HumanReview(Frozen):
    case_id: Text
    reviewer_id: Text
    label: Literal["malicious", "benign", "needs_review"]
    rationale: Annotated[str, Field(min_length=20, max_length=4000)]
    cited_event_ids: Annotated[tuple[Text, ...], Field(min_length=1, max_length=500)]
    blind_to_model_outputs: Literal[True]
    independent_of_case_author: Literal[True]
    human_attestation_reference: Text


class Adjudication(Frozen):
    case_id: Text
    adjudicator_id: Text
    label: Literal["malicious", "benign", "needs_review"]
    rationale: Annotated[str, Field(min_length=20, max_length=4000)]
    attestation_reference: Text


class ReviewManifest(Frozen):
    schema_version: Literal["review-gate-1.0"] = "review-gate-1.0"
    frozen_code_sha256: Digest
    frozen_rules_sha256: Digest
    dataset_sha256: Digest
    preregistration_reference: Text
    cases: Annotated[tuple[ProspectiveCase, ...], Field(min_length=1, max_length=500)]
    reviews: Annotated[tuple[HumanReview, ...], Field(max_length=1000)]
    adjudications: Annotated[tuple[Adjudication, ...], Field(max_length=500)] = ()


def check_review_gate(
    manifest: ReviewManifest, contaminated_families: set[str]
) -> dict[str, object]:
    cases = {c.case_id: c for c in manifest.cases}
    if len(cases) != len(manifest.cases):
        raise ValueError("Duplicate case ID")
    dev = {c.family_id for c in manifest.cases if c.partition == "development"}
    held = [c for c in manifest.cases if c.partition == "holdout"]
    if not held or {c.family_id for c in held} & (dev | contaminated_families):
        raise ValueError("Missing holdout or contaminated/overlapping family")
    reviews: dict[str, dict[str, HumanReview]] = {}
    for review in manifest.reviews:
        case = cases.get(review.case_id)
        if case is None or review.reviewer_id == case.author_id:
            raise ValueError("Unknown case or author reviewing own case")
        if not set(review.cited_event_ids) <= set(case.source_event_ids):
            raise ValueError("Review cites unavailable evidence")
        group = reviews.setdefault(review.case_id, {})
        if review.reviewer_id in group:
            raise ValueError("Repeated reviewer for case")
        group[review.reviewer_id] = review
    adjudications = {a.case_id: a for a in manifest.adjudications}
    if len(adjudications) != len(manifest.adjudications) or not set(adjudications) <= set(cases):
        raise ValueError("Unknown or duplicate adjudication")
    labels = {}
    for case in held:
        pair = reviews.get(case.case_id, {})
        if len(pair) != 2:
            raise ValueError("Exactly two independent human reviews required per holdout case")
        label_set = {r.label for r in pair.values()}
        adjudication = adjudications.get(case.case_id)
        if len(label_set) == 1 and adjudication is None:
            labels[case.case_id] = next(iter(label_set))
        else:
            if adjudication is None or adjudication.adjudicator_id in {*pair, case.author_id}:
                raise ValueError("Independent adjudication required for disagreement")
            labels[case.case_id] = adjudication.label
    return dict(
        structural_review_gate="passed",
        holdout_cases=len(held),
        holdout_families=len({c.family_id for c in held}),
        adjudicated_labels=labels,
        independent_human_identity_verified=False,
        limitation="A human custodian must verify attestations and the signed freeze.",
    )
