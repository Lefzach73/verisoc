"""Explicit original development controls; no held-out or independent-label claim."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from verisoc.evidence.rules import RULES, RULESET_VERSION

ROOT = Path(__file__).resolve().parents[1]
TYPES = (
    "burst",
    "below_count",
    "slow_failures",
    "ordered_success",
    "wrong_user_success",
    "wrong_host_success",
    "equal_time",
    "reverse_time",
    "distinct_accounts",
    "below_distinct",
    "mixed_sources",
    "cross_host_names",
    "missing_user",
    "lower_image",
    "upper_image",
    "suffix_image",
    "path_image",
    "flow_only",
    "authorized_reset_lookalike",
    "authorized_image_lookalike",
)


def main():
    folder = ROOT / "fixtures/v04-dev"
    if folder.exists():
        raise SystemExit("Refusing to overwrite development fixtures")
    rows = []
    labels = []
    for index, name in enumerate(TYPES):
        for variant in range(2):
            tenant = ("demo-a", "demo-b")[variant]
            start = datetime(2027, 2, 1, tzinfo=UTC) + timedelta(hours=index * 2 + variant)

            def event(code, seconds, _tenant=tenant, _start=start, **extra):
                row = dict(
                    fixture_tenant=_tenant,
                    event_code=code,
                    timestamp=(_start + timedelta(seconds=seconds)).isoformat(),
                    host="dev-host",
                    user="dev-user",
                    message=f"Inert development record {seconds}",
                )
                row.update(extra)
                return row

            n = 4 if name == "below_count" else 6
            local = [event(4625, i * (100 if name == "slow_failures" else 10)) for i in range(n)]
            expected = {"failed_login_burst"}
            intent = "needs_review"
            if name in ("below_count", "slow_failures"):
                expected = set()
                intent = "benign"
            if name in (
                "ordered_success",
                "wrong_user_success",
                "wrong_host_success",
                "equal_time",
                "reverse_time",
                "authorized_reset_lookalike",
            ):
                success = event(
                    4624, 0 if name == "equal_time" else -1 if name == "reverse_time" else 80
                )
                if name == "wrong_user_success":
                    success["user"] = "another-user"
                if name == "wrong_host_success":
                    success["host"] = "another-host"
                local.append(success)
                if name in ("ordered_success", "authorized_reset_lookalike"):
                    expected.add("success_after_failures")
                    intent = "malicious" if name == "ordered_success" else "benign"
            if name in ("distinct_accounts", "below_distinct", "mixed_sources"):
                for i, row in enumerate(local):
                    row["user"] = f"dev-user-{i % 4 if name == 'below_distinct' else i}"
                    row["src_ip"] = "192.0.2.1" if name != "mixed_sources" or i < 3 else "192.0.2.2"
                expected = set() if name == "below_distinct" else {"multi_account_failures"}
                if name == "distinct_accounts":
                    expected.add("source_account_failures")
                    intent = "malicious"
                elif name == "below_distinct":
                    intent = "benign"
            if name == "cross_host_names":
                for i, row in enumerate(local):
                    row["host"] = f"dev-host-{i}"
                expected = set()
                intent = "benign"
            if name == "missing_user":
                for row in local:
                    row["user"] = None
                expected = set()
            if "image" in name:
                image = {
                    "lower_image": "lab-indicator.exe",
                    "upper_image": "LAB-INDICATOR.EXE",
                    "suffix_image": "lab-indicator.exe.backup",
                    "path_image": "C:\\Tools\\lab-indicator.exe",
                    "authorized_image_lookalike": "lab-indicator.exe",
                }[name]
                local = [event(4688, 0, process=image)]
                expected = set() if name == "suffix_image" else {"windows_image_match"}
                intent = (
                    "benign"
                    if name in ("suffix_image", "authorized_image_lookalike")
                    else "malicious"
                )
            if name == "flow_only":
                local = [
                    event(3, i, src_ip="192.0.2.1", dst_ip="198.51.100.1", dst_port=4444)
                    for i in range(6)
                ]
                expected = set()
                intent = "benign"
            if variant:
                local = list(reversed(local))
            labels.append(
                dict(
                    scenario_id=f"v04-dev-{index:02d}-{variant}",
                    template=name,
                    family="process"
                    if "image" in name
                    else "flow"
                    if name == "flow_only"
                    else "auth",
                    tenant=tenant,
                    partition="development",
                    incident_label=intent,
                    expected_predicates=sorted(expected),
                    start_at=min(r["timestamp"] for r in local),
                    end_at=max(r["timestamp"] for r in local),
                    annotation="author_defined_internal_controls",
                )
            )
            rows.extend(local)
    folder.mkdir()
    for name, data in [("events.jsonl", rows), ("cases.jsonl", labels)]:
        (folder / name).write_text("\n".join(json.dumps(r, sort_keys=True) for r in data) + "\n")
    (ROOT / "config/v04_rule_snapshot.json").write_text(
        json.dumps(
            {
                "ruleset": RULESET_VERSION,
                "threshold_basis": (
                    "Five events / 300 seconds inherited from native v0.3, "
                    "not fitted on cohort labels. Distinct count five is a development "
                    "hypothesis, not a production threshold."
                ),
                "rules": [r.model_dump(mode="json") for r in RULES.values()],
            },
            indent=2,
        )
        + "\n"
    )
    print("Created", len(labels), "development cases and", len(rows), "source rows.")


if __name__ == "__main__":
    main()
