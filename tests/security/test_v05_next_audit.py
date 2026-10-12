"""Independent adversarial audit controls; every event/review below is synthetic."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.evaluation.v05_intake import ContaminationIndex, IntakeManifest, validate_intake

EMPTY = ContaminationIndex(
    case_ids=(), origin_ids=(), family_ids=(), signatures=(), source_hashes=()
)


def overlapping_intake(root, partitions):
    start = datetime(2027, 8, 1, tzinfo=UTC)
    content = (
        "\n".join(
            json.dumps(
                dict(
                    timestamp=(start + timedelta(minutes=i)).isoformat(),
                    event_code=code,
                    host="audit-host",
                    user="audit-user",
                )
            )
            for i, code in enumerate((4625, 4624, 4688))
        )
        + "\n"
    ).encode()
    permission = b"Synthetic audit controls only; no independent permission is asserted."
    (root / "events.jsonl").write_bytes(content)
    (root / "permission.txt").write_bytes(permission)
    return IntakeManifest.model_validate(
        dict(
            study_id="overlap-audit",
            provenance="external_independent_candidate",
            custodian_id="test-custodian",
            license_id="MIT",
            privacy_attestation="Synthetic audit inputs only.",
            permission_file="permission.txt",
            files=[
                dict(path="events.jsonl", sha256=digest(content), role="events"),
                dict(path="permission.txt", sha256=digest(permission), role="permission"),
            ],
            cases=[
                dict(
                    case_id=f"case-{i}",
                    family_id=f"declared-family-{i}",
                    origin_incident_id=f"declared-origin-{i}",
                    author_id="test-author",
                    tenant_id=str(demo_tenant("demo-a")),
                    dataset_id="overlap-audit",
                    event_file="events.jsonl",
                    row_indexes=rows,
                    partition=partition,
                )
                for i, (rows, partition) in enumerate(
                    zip(((1, 2), (2, 3)), partitions, strict=True)
                )
            ],
        )
    )


@pytest.mark.parametrize("partitions", [("development", "holdout"), ("calibration", "holdout")])
def test_intake_rejects_shared_source_events_across_partitions(tmp_path, partitions):
    """Different family labels and window signatures do not remove a shared raw event."""
    manifest = overlapping_intake(tmp_path, partitions)
    with pytest.raises(ValueError, match="(?i)(overlap|shared|partition|source)"):
        validate_intake(tmp_path, manifest, EMPTY)


def test_holdout_cannot_double_count_overlapping_observation_windows(tmp_path):
    manifest = overlapping_intake(tmp_path, ("holdout", "holdout"))
    with pytest.raises(ValueError, match="(?i)(overlap|shared|holdout|source)"):
        validate_intake(tmp_path, manifest, EMPTY)


@pytest.mark.parametrize("nested_checkout", [False, True])
def test_freeze_is_runnable_from_an_extracted_source_archive(
    tmp_path, monkeypatch, nested_checkout
):
    """A source ZIP has no .git directory; source hashing must still reproduce the study."""
    import shutil
    import subprocess
    from pathlib import Path

    from verisoc.evaluation.v05_runner import MODEL_ID
    from verisoc.evaluation.v05_study import StudyPlan, freeze_study, verify_study

    source = Path(__file__).resolve().parents[2]
    archive_parent = tmp_path
    if nested_checkout:
        archive_parent = tmp_path / "unrelated-checkout"
        archive_parent.mkdir()
        subprocess.run(["git", "init", "-q", str(archive_parent)], check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Synthetic Audit",
                "-c",
                "user.email=synthetic-audit@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "Temporary synthetic audit checkout",
            ],
            cwd=archive_parent,
            check=True,
        )
    archive = archive_parent / "extracted-archive"
    shutil.copytree(source / "src/verisoc", archive / "src/verisoc")
    for name in ("uv.lock", "pyproject.toml"):
        shutil.copyfile(source / name, archive / name)
    # Ensure no enclosing checkout can supply unrelated Git identity to the archive.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    manifest = overlapping_intake(tmp_path, ("development", "development"))
    study = tmp_path / "study"
    freeze_study(
        tmp_path,
        manifest,
        EMPTY,
        StudyPlan(study_id=manifest.study_id, model_id=MODEL_ID, model_revision="1.0"),
        archive,
        study,
    )
    frozen = verify_study(study, archive)
    assert frozen["source_code_sha256"]
    assert frozen["git_sha"] is None
    assert frozen["source_origin"] == "source_archive"


def test_visible_approval_carries_cross_case_ticket_revocation_without_foreign_bindings(tmp_path):
    from verisoc.evaluation.v05_context_inputs import StudyOracle, visible_context
    from verisoc.v05.context_models import ContextAuthority, ContextBundle

    manifest = overlapping_intake(tmp_path, ("development", "development"))
    source = (tmp_path / "events.jsonl").read_bytes()
    tenant = manifest.cases[0].tenant_id
    oracle = StudyOracle(source, tenant, "overlap-audit")
    proofs = list(oracle.proofs.values())
    start = datetime(2027, 8, 1, tzinfo=UTC)
    approved = dict(
        kind="approved_password_reset",
        status="approved",
        ticket_id="same-source-ticket",
        dataset_id="overlap-audit",
        event_source_sha256=digest(source),
        host_id=oracle.identity("audit-host", tenant),
        principal_id=oracle.identity("audit-user", tenant),
        approved_at=(start - timedelta(minutes=1)).isoformat(),
        valid_from=start.isoformat(),
        valid_until=(start + timedelta(minutes=30)).isoformat(),
        bindings=[
            dict(event_id=str(proofs[0].event_id), canonical_sha256=proofs[0].canonical_sha256)
        ],
    )
    revoked = dict(
        approved,
        status="revoked",
        bindings=[
            dict(event_id=str(proofs[1].event_id), canonical_sha256=proofs[1].canonical_sha256)
        ],
    )
    body = (json.dumps(approved) + "\n" + json.dumps(revoked) + "\n").encode()
    bundle = ContextBundle(
        authority=ContextAuthority(
            tenant_id=tenant,
            dataset_id="overlap-audit",
            source_id="test-context",
            file_sha256=digest(body),
            authorization_reference="synthetic-test-only",
        ),
        content=body,
    )
    visible = visible_context(bundle, {proofs[0].event_id})
    encoded = json.dumps(visible)
    assert "revoked" in encoded, "Review evidence hides revocation used by the runtime verifier"
    assert str(proofs[1].event_id) not in encoded, "Revocation must not leak another case's IDs"


@pytest.mark.parametrize("mutation", ["row_hash", "duplicate", "unknown", "proposal_body"])
def test_scorer_rejects_shared_proposal_hash_not_bound_to_recorded_proposal(tmp_path, mutation):
    from pathlib import Path

    from verisoc.evaluation.v05_review import SubmittedReview, export_blind_forms
    from verisoc.evaluation.v05_runner import MODEL_ID, run_frozen_mock
    from verisoc.evaluation.v05_scoring import score_reviewed_run
    from verisoc.evaluation.v05_study import StudyPlan, freeze_study

    root = Path(__file__).resolve().parents[2]
    manifest = overlapping_intake(tmp_path, ("development", "development"))
    study, run, forms = (tmp_path / name for name in ("study", "run", "forms"))
    freeze_study(
        tmp_path,
        manifest,
        EMPTY,
        StudyPlan(study_id=manifest.study_id, model_id=MODEL_ID, model_revision="1.0"),
        root,
        study,
    )
    run_frozen_mock(study, root, run)
    export_blind_forms(study, ("synthetic-reviewer-a", "synthetic-reviewer-b"), forms)
    mapping = json.loads((forms / "custodian-mapping.json").read_text())
    packets = json.loads((forms / "blind-packets.json").read_text())
    reviews = tuple(
        SubmittedReview(
            blinded_case_id=packet["blinded_case_id"],
            reviewer_id=reviewer,
            packet_sha256=mapping["packet_sha256"],
            label="benign",
            rationale="Synthetic audit submission, not an actual human review.",
            cited_event_ids=(packet["evidence"][0]["event_id"],),
            blind_to_outputs=True,
            independent_of_authors=True,
            human_attestation_reference="synthetic-test-only",
            submitted_at=datetime.now(UTC),
        )
        for packet in packets
        for reviewer in mapping["reviewer_ids"]
    )
    if mutation == "row_hash":
        altered = "rows.json"
        rows = json.loads((run / altered).read_text())
        for row in rows:
            if row["arm"] in ("B2", "B3", "B3-hybrid-v0.5"):
                row["shared_proposal_sha256"] = "0" * 64
        (run / altered).write_text(json.dumps(rows))
    else:
        altered = "proposals.json"
        proposals = json.loads((run / altered).read_text())
        if mutation == "duplicate":
            proposals.append(proposals[0])
        elif mutation == "unknown":
            proposals.append(dict(proposals[0], case_id="unfrozen-case"))
        else:
            proposals[0]["candidate"]["proposed_verdict"] = "malicious"
        (run / altered).write_text(json.dumps(proposals))
    receipt = json.loads((run / "manifest.json").read_text())
    receipt["output_sha256"][altered] = digest((run / altered).read_bytes())
    (run / "manifest.json").write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="(?i)(proposal|pair)"):
        score_reviewed_run(study, run, forms, reviews, None, tmp_path / "score")


def test_copied_reordered_source_does_not_remove_cross_partition_overlap(tmp_path):
    manifest = overlapping_intake(tmp_path, ("development", "holdout"))
    copied = b"\n".join(reversed((tmp_path / "events.jsonl").read_bytes().splitlines())) + b"\n"
    (tmp_path / "renamed-copy.jsonl").write_bytes(copied)
    data = manifest.model_dump(mode="json")
    data["files"].append(dict(path="renamed-copy.jsonl", role="events", sha256=digest(copied)))
    data["cases"][1].update(
        event_file="renamed-copy.jsonl", dataset_id="renamed-dataset", row_indexes=[1, 2]
    )
    with pytest.raises(ValueError, match="(?i)(overlap|shared|partition|source)"):
        validate_intake(tmp_path, IntakeManifest.model_validate(data), EMPTY)
