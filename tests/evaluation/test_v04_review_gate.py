import pytest
from pydantic import ValidationError

from verisoc.evaluation.review_gate import ReviewManifest, check_review_gate


def synthetic_manifest():
    return dict(
        frozen_code_sha256="0" * 64,
        frozen_rules_sha256="1" * 64,
        dataset_sha256="2" * 64,
        preregistration_reference="unit-test-only-not-real-registration",
        cases=[
            dict(
                case_id="c",
                family_id="new-family",
                author_id="fixture-author",
                source_sha256="3" * 64,
                source_event_ids=["e"],
                permission_reference="synthetic-test",
                partition="holdout",
            )
        ],
        reviews=[
            dict(
                case_id="c",
                reviewer_id=f"test-reviewer-{i}",
                label="needs_review",
                rationale="Synthetic unit test review, not a real human label.",
                cited_event_ids=["e"],
                blind_to_model_outputs=True,
                independent_of_case_author=True,
                human_attestation_reference="synthetic-test-only",
            )
            for i in (1, 2)
        ],
    )


def test_structural_review_gate_does_not_certify_human_identity():
    result = check_review_gate(ReviewManifest.model_validate(synthetic_manifest()), set())
    assert result["structural_review_gate"] == "passed"
    assert result["independent_human_identity_verified"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "one_review",
        "same_reviewer",
        "author",
        "foreign_citation",
        "disagreement",
        "overlap",
        "no_holdout",
        "not_blind",
    ],
)
def test_incomplete_or_contaminated_review_never_passes(mutation):
    data = synthetic_manifest()
    contaminated = set()
    if mutation == "one_review":
        data["reviews"].pop()
    if mutation == "same_reviewer":
        data["reviews"][1]["reviewer_id"] = data["reviews"][0]["reviewer_id"]
    if mutation == "author":
        data["reviews"][1]["reviewer_id"] = "fixture-author"
    if mutation == "foreign_citation":
        data["reviews"][1]["cited_event_ids"] = ["foreign"]
    if mutation == "disagreement":
        data["reviews"][1]["label"] = "malicious"
    if mutation == "overlap":
        contaminated = {"new-family"}
    if mutation == "no_holdout":
        data["cases"][0]["partition"] = "development"
    if mutation == "not_blind":
        data["reviews"][1]["blind_to_model_outputs"] = False
    with pytest.raises((ValueError, ValidationError)):
        check_review_gate(ReviewManifest.model_validate(data), contaminated)
