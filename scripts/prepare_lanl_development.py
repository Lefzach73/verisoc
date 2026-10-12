"""Opt-in bounded acquisition of exact public development telemetry, with receipts."""

import argparse
import json
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid5

from verisoc.core.provenance import digest
from verisoc.evaluation.v05_lanl import convert_source, decompress_prefix
from verisoc.evaluation.v05_raw_oracle import SingleTenantOracle
from verisoc.evidence.registry import EvidenceRegistry
from verisoc.ingest.importer import import_jsonl
from verisoc.investigation.evidence_pipeline import CaseWindow, open_window, view
from verisoc.storage.repository import Database
from verisoc.v05.triage import triage

LANL_PAGE = "https://csr.lanl.gov/data/2017/"
LANL_DATA = "https://csr.lanl.gov/data-fence/unified-host-network-dataset-2017/wls/wls_day-01.bz2"
SPLUNK_COMMIT = "0169dc69e8824ea88e71225289a08429c569d237"
SPLUNK_PATH = "datasets/attack_techniques/T1003.003/atomic_red_team/4688_windows-security.log"
SPLUNK_RAW = "https://raw.githubusercontent.com/splunk/attack_data/" + SPLUNK_COMMIT + "/"
SPLUNK_DATA = (
    "https://media.githubusercontent.com/media/splunk/attack_data/"
    + SPLUNK_COMMIT
    + "/"
    + SPLUNK_PATH
)
SPLUNK_SHA256 = "81e1d4e381f4dc38b97c48f9fa5b0ab0b098810c321b7d4599029a9f22530259"
SPLUNK_PROFILES = {
    "splunk": (SPLUNK_PATH, SPLUNK_SHA256, 11176),
    "splunk-auth": (
        "datasets/attack_techniques/T1110.003/"
        "purplesharp_multiple_users_from_process_xml/windows-security.log",
        "b9886899bdceb4c3c99aa19eeb23ef00da7df93013e9526815d40bdd1c2c81c1",
        311246,
    ),
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def fetch(url: str, cap: int) -> tuple[bytes, dict[str, Any]]:
    """No credentials, cookies, redirect following, retries or unbounded response body."""
    request = urllib.request.Request(
        url,
        headers={
            "Range": f"bytes=0-{cap - 1}",
            "Accept-Encoding": "identity",
            "User-Agent": "VeriSOC-public-interoperability/0.5",
        },
    )
    receipt: dict[str, Any] = {
        "url": url,
        "requested_range": f"bytes=0-{cap - 1}",
        "started_at": datetime.now(UTC).isoformat(),
        "body_byte_cap": cap,
    }
    opener = urllib.request.build_opener(NoRedirect)
    try:
        try:
            response = opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            content = response.read(cap)
            headers = {
                name: response.headers[name]
                for name in (
                    "Content-Type",
                    "Content-Length",
                    "Content-Range",
                    "Content-Encoding",
                    "ETag",
                    "Last-Modified",
                    "Accept-Ranges",
                )
                if name in response.headers
            }
            receipt.update(status=response.status, headers=headers)
    except (OSError, urllib.error.URLError) as exc:
        content = b""
        receipt.update(status=None, error_type=type(exc).__name__)
    receipt.update(body_bytes=len(content), body_sha256=digest(content))
    return content, receipt


def write_json(path: Path, value: object) -> None:
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def full_response(receipt: dict[str, Any]) -> bool:
    headers = receipt["headers"]
    if headers.get("Content-Encoding", "identity") != "identity":
        raise ValueError("unexpected_content_encoding")
    length = receipt["body_bytes"]
    if receipt["status"] == 206:
        match = re.fullmatch(r"bytes 0-(\d+)/(\d+)", headers.get("Content-Range", ""))
        if not match or int(match[1]) + 1 != length:
            raise ValueError("partial_response_scope_mismatch")
        return int(match[2]) == length
    return str(headers.get("Content-Length")) == str(length)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("lanl", *SPLUNK_PROFILES), required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fetch-public-data", action="store_true")
    parser.add_argument("--offline-from", type=Path)
    args = parser.parse_args()
    if bool(args.fetch_public_data) == bool(args.offline_from):
        parser.error("Choose --fetch-public-data or --offline-from, exclusively")
    if args.raw.exists() or args.out.exists():
        parser.error("Both destinations must be new")
    args.raw.mkdir(parents=True)
    args.out.mkdir(parents=True)
    receipts = []
    summary: dict[str, Any] = {
        "status": "BLOCKED",
        "source_profile": args.source,
        "partition": "development",
        "research_validity": "interoperability_only",
        "gold_labels": None,
        "independent_holdout_cases": 0,
        "human_reviews": 0,
        "network_body_byte_limit": 2 * 1024 * 1024,
    }

    def acquire(name: str, url: str, cap: int) -> tuple[bytes, dict[str, Any]]:
        if args.offline_from:
            with (args.offline_from / name).open("rb") as handle:
                content = handle.read(cap + 1)
            receipt = json.loads((args.offline_from / (name + ".receipt.json")).read_text())
            if (
                len(content) > cap
                or digest(content) != receipt["body_sha256"]
                or receipt["url"] != url
                or receipt["body_bytes"] != len(content)
            ):
                raise ValueError("cached_receipt_mismatch")
            receipt["transport"] = "verified_local_replay"
        else:
            content, receipt = fetch(url, cap)
            receipt["transport"] = "https"
        receipts.append(receipt)
        (args.raw / name).write_bytes(content)
        write_json(args.raw / (name + ".receipt.json"), receipt)
        return content, receipt

    try:
        kind: Literal["lanl_jsonl", "windows_xml"]
        license_url = LANL_PAGE if args.source == "lanl" else SPLUNK_RAW + "LICENSE"
        license_bytes, license_receipt = acquire("license-source.txt", license_url, 262144)
        if license_receipt["status"] not in (200, 206):
            raise ValueError("license_source_unavailable")
        if args.source == "lanl":
            if b"waived all copyright and related or neighboring rights" not in license_bytes:
                raise ValueError("license_waiver_not_verified")
            data, receipt = acquire("source-prefix.bz2", LANL_DATA, 1048576)
            summary["license_observed"] = "LANL published copyright and related-rights waiver"
            if receipt["status"] not in (200, 206):
                raise ValueError("data_access_requires_authorization_no_bypass")
            source, compression_complete = decompress_prefix(data)
            complete = compression_complete and full_response(receipt)
            kind = "lanl_jsonl"
        else:
            if b"Apache License" not in license_bytes or b"Version 2.0" not in license_bytes:
                raise ValueError("apache_license_not_verified")
            source_path, expected_sha, expected_size = SPLUNK_PROFILES[args.source]
            pointer, pointer_receipt = acquire("lfs-pointer.txt", SPLUNK_RAW + source_path, 4096)
            if pointer_receipt["status"] not in (200, 206) or (
                f"oid sha256:{expected_sha}".encode() not in pointer
                or f"size {expected_size}".encode() not in pointer
            ):
                raise ValueError("source_pointer_mismatch")
            data_url = (
                "https://media.githubusercontent.com/media/splunk/attack_data/"
                + SPLUNK_COMMIT
                + "/"
                + source_path
            )
            data, receipt = acquire("windows-security.log", data_url, expected_size + 1)
            if (
                receipt["status"] not in (200, 206)
                or len(data) != expected_size
                or digest(data) != expected_sha
            ):
                raise ValueError("source_hash_size_or_download_mismatch")
            if not full_response(receipt):
                raise ValueError("incomplete_lfs_response")
            source, complete, kind = data, True, "windows_xml"
            summary.update(
                license_observed="Apache-2.0",
                source_commit=SPLUNK_COMMIT,
                provenance="public_controlled_attack_range_recording",
            )
        (args.raw / "admitted-source.bin").write_bytes(source)
        derived, provenance = convert_source(source, kind, complete=complete)
        write_json(args.out / "provenance.json", provenance)
        if not derived:
            raise ValueError("no_supported_records_in_bounded_sample")
        if not provenance["runtime_admissible"]:
            preview = []
            for line, lineage in zip(derived.splitlines(), provenance["lineage"], strict=True):
                item = json.loads(line)
                item.pop("timestamp")
                item.pop("message")
                item["relative_seconds"] = lineage["source_relative_seconds"]
                preview.append(item)
            write_json(
                args.out / "relative-time-preview.json",
                {
                    "runtime_admissible": False,
                    "calendar_time_known": False,
                    "scope": "source_mapping_preview_only",
                    "rows": preview,
                },
            )
            summary.update(
                scope="source_mapping_preview_only",
                runtime_admissible=False,
                preview_records=len(preview),
                imported_events=0,
                source_sha256=digest(source),
                source_complete=complete,
            )
            raise ValueError("native_relative_time_runtime_support_required")
        (args.out / "events.jsonl").write_bytes(derived)
        database = Database("sqlite://")
        tenant = uuid5(NAMESPACE_URL, "verisoc/public-development/" + args.source)
        dataset = "public-interop-" + digest(derived)[:16]
        oracle = SingleTenantOracle(derived, tenant, dataset)
        try:
            with database.scope(tenant) as repo:
                imported = import_jsonl(repo, derived, dataset)
                mismatches = sum(
                    repo.get_event(eid).canonical_sha256 != oracle.proofs[eid].canonical_sha256
                    for eid in imported.event_ids
                )
                repeated = import_jsonl(repo, derived, dataset)
                timestamps = [repo.get_event(eid).occurred_at for eid in imported.event_ids]
                case = open_window(
                    repo,
                    CaseWindow(
                        dataset_id=dataset, start_at=min(timestamps), end_at=max(timestamps)
                    ),
                )
                report = triage(repo, case)
                registry = EvidenceRegistry(repo, case)
                emitted = report.verified_observations + report.indicator_evidence
                unsupported = sum(
                    not oracle.supports_fact(case, registry.get(fact.fact_id))
                    or view(registry.get(fact.fact_id)) != fact
                    for fact in emitted
                )
            write_json(args.out / "import.json", imported.model_dump(mode="json"))
            write_json(args.out / "case.json", case.model_dump(mode="json"))
            write_json(args.out / "triage.json", report.model_dump(mode="json"))
        finally:
            database.engine.dispose()
        if mismatches or repeated.accepted or unsupported:
            raise ValueError("canonical_fact_or_idempotence_discrepancy")
        summary.update(
            status="PASS",
            scope="source_import_deterministic_triage_and_independent_evidence_checks",
            source_sha256=digest(source),
            derived_sha256=digest(derived),
            source_complete=complete,
            accepted_records=provenance["accepted"],
            rejected_records=provenance["rejected"],
            imported_events=imported.accepted,
            duplicate_records=imported.duplicates,
            canonical_checks=len(imported.event_ids),
            canonical_discrepancies=mismatches,
            reimport_new_events=repeated.accepted,
            mapping_checks=provenance["independent_mapping_checks"],
            mapping_discrepancies=provenance["independent_mapping_discrepancies"],
            observed_facts=len(report.verified_observations),
            indicator_facts=len(report.indicator_evidence),
            emitted_fact_checks=len(emitted),
            unsupported_emitted_facts=unsupported,
            triage_flag=report.triage_flag,
            disposition=report.disposition,
            incident_verdict=report.incident_verdict,
            reason_codes=report.reason_codes,
            missing_fields=report.missing_fields,
            case_span_seconds=(case.end_at - case.start_at).total_seconds(),
            efficacy_metrics=None,
            model_calls=0,
        )
    except (ValueError, OSError) as exc:
        summary["blocker"] = str(exc)
    finally:
        summary["network_body_bytes_received"] = sum(
            r["body_bytes"] for r in receipts if r.get("transport") == "https"
        )
        summary["cached_body_bytes_replayed"] = sum(
            r["body_bytes"] for r in receipts if r.get("transport") == "verified_local_replay"
        )
        summary["requests"] = receipts
        write_json(args.out / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
