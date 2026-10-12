"""Create an explicitly synthetic, DEV-only intake example. Never makes human submissions."""

import argparse
import json
from pathlib import Path
from uuid import UUID

from verisoc.core.ids import demo_tenant
from verisoc.core.provenance import digest
from verisoc.evaluation.fact_oracle import RawFactOracle
from verisoc.evaluation.v05_intake import IntakeManifest
from verisoc.evaluation.v05_raw_oracle import SingleTenantOracle
from verisoc.evaluation.v05_runner import MODEL_ID
from verisoc.evaluation.v05_study import StudyPlan, json_bytes, write_new

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--with-context", action="store_true")
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=False)
source = root / "fixtures/v05-dev"
raw = [json.loads(line) for line in (source / "events.jsonl").read_text().splitlines()]
labels = [json.loads(line) for line in (source / "cases.jsonl").read_text().splitlines()]
# Four demonstrator cases; selecting controls is not a prospective dataset or power analysis.
selected = [labels[i] for i in (0, 2, 8, 10)]
files = []
cases = []
pins = []
original = RawFactOracle((source / "events.jsonl").read_bytes(), "v05-dev")
for number, label in enumerate(selected):
    rows = [
        {k: v for k, v in r.items() if k != "fixture_tenant"}
        for r in raw
        if r["fixture_tenant"] == label["tenant"]
        and label["start_at"] <= r["timestamp"] <= label["end_at"]
    ]
    content = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode()
    name = f"events-{number}.jsonl"
    write_new(args.out / name, content)
    files.append(dict(path=name, sha256=digest(content), role="events"))
    cases.append(
        dict(
            case_id=label["scenario_id"],
            family_id=label["family"],
            origin_incident_id=label["scenario_id"],
            author_id="synthetic-fixture-author",
            tenant_id=str(demo_tenant(label["tenant"])),
            dataset_id=f"custody-demo-{number}",
            event_file=name,
            row_indexes=list(range(1, len(rows) + 1)),
            partition="development",
        )
    )
    if args.with_context:
        # Rebind only existing synthetic activity records to this extracted source file.
        # Do not invent approval for the two controls whose sources have no activity record.
        oracle = SingleTenantOracle(content, demo_tenant(label["tenant"]), f"custody-demo-{number}")
        proofs = {p.raw_row_sha256: p for p in oracle.proofs.values()}
        records = []
        for line in (source / f"context-{label['tenant']}.jsonl").read_text().splitlines():
            record = json.loads(line)
            old = [original.proofs[UUID(b["event_id"])] for b in record["bindings"]]
            if not all(p.raw_row_sha256 in proofs for p in old):
                continue
            record["dataset_id"] = f"custody-demo-{number}"
            record["event_source_sha256"] = digest(content)
            record["bindings"] = [
                dict(
                    event_id=str(proofs[p.raw_row_sha256].event_id),
                    canonical_sha256=proofs[p.raw_row_sha256].canonical_sha256,
                )
                for p in old
            ]
            records.append(record)
        if records:
            name = f"context-{number}.jsonl"
            body = ("".join(json.dumps(r, sort_keys=True) + "\n" for r in records)).encode()
            write_new(args.out / name, body)
            files.append(dict(path=name, sha256=digest(body), role="context"))
            pin = f"synthetic-context-{number}"
            cases[-1]["context_pins"] = [pin]
            pins.append(
                dict(
                    pin_id=pin,
                    file=name,
                    authority=dict(
                        tenant_id=str(demo_tenant(label["tenant"])),
                        dataset_id=f"custody-demo-{number}",
                        source_id=pin,
                        file_sha256=digest(body),
                        authorization_reference="existing synthetic v05-dev controls only",
                    ),
                )
            )
permission = (
    b"Author-generated synthetic software controls under the project MIT license. "
    b"No external human signoff.\n"
)
write_new(args.out / "permission.txt", permission)
files.append(dict(path="permission.txt", sha256=digest(permission), role="permission"))
manifest = IntakeManifest.model_validate(
    dict(
        study_id="v05-custody-demo",
        provenance="synthetic_development",
        custodian_id="unassigned-custodian",
        license_id="MIT",
        privacy_attestation="synthetic controls only",
        permission_file="permission.txt",
        files=files,
        cases=cases,
        context_sources=pins,
    )
)
write_new(args.out / "intake.json", json_bytes(manifest.model_dump(mode="json")))
write_new(
    args.out / "plan.json",
    json_bytes(
        StudyPlan(
            study_id=manifest.study_id,
            model_id=MODEL_ID,
            model_revision="1.0",
            context_condition="with_context" if args.with_context else "events_only",
        ).model_dump(mode="json")
    ),
)
print("Prepared 4 DEV-only demonstration cases; no independent cases or human reviews created.")
