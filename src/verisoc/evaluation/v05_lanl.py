"""Bounded public telemetry interoperability; inspected development data, never gold."""

import bz2
import json
import ntpath
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from verisoc.core.models import RawEvent
from verisoc.core.provenance import digest
from verisoc.v05.context_source import unique_fields

MAX_BYTES = 2 * 1024 * 1024
MAX_ROWS = 500
ORIGIN = datetime(2000, 1, 1, tzinfo=UTC)
ORIGIN_WARNING = "Artificial ordering anchor; not the calendar time of the LANL event"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
LANL_KEYS = {
    "Time",
    "EventID",
    "LogHost",
    "Computer",
    "LogonType",
    "LogonTypeDescription",
    "UserName",
    "DomainName",
    "LogonID",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectLogonID",
    "Status",
    "Source",
    "ServiceName",
    "Destination",
    "AuthenticationPackage",
    "FailureReason",
    "ProcessName",
    "ProcessID",
    "ParentProcessName",
    "ParentProcessID",
}


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or value in ("?", "-"):
        raise ValueError("missing_identity_or_process")
    if len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid_text")
    return value


def _principal(domain: object, user: object) -> str:
    d, u = _text(domain), _text(user)
    if "\\" in d or "\\" in u:
        raise ValueError("ambiguous_principal_namespace")
    return d + "\\" + u


def map_lanl(record: dict[str, Any]) -> RawEvent:
    """Map only documented fields; Time is intentionally an artificial ordering axis."""
    if not isinstance(record, dict) or record.keys() - LANL_KEYS:
        raise ValueError("unknown_lanl_field")
    code = record.get("EventID")
    if type(code) is not int or code not in (4624, 4625, 4688):
        raise ValueError("unsupported_event_code")
    seconds = record.get("Time")
    if type(seconds) is not int or not 0 <= seconds <= 366 * 86400:
        raise ValueError("invalid_relative_time")
    hosts = [_text(record[k]) for k in ("LogHost", "Computer") if k in record]
    if not hosts or len(set(hosts)) != 1:
        raise ValueError("missing_or_conflicting_host")
    if code in (4624, 4625) and "Status" in record:
        status = record["Status"]
        if not isinstance(status, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", status):
            raise ValueError("invalid_auth_status")
        if (int(status, 16) == 0) != (code == 4624):
            raise ValueError("conflicting_auth_status")
    return RawEvent.model_validate(
        {
            "event_code": code,
            "timestamp": ORIGIN + timedelta(seconds=seconds),
            "host": hosts[0],
            "user": _principal(record.get("DomainName"), record.get("UserName")),
            "process": _text(record.get("ProcessName")) if code == 4688 else None,
            "message": ORIGIN_WARNING,
        }
    )


def _xml_parts(xml: bytes) -> tuple[Any, dict[str, str | None]]:
    try:
        from defusedxml.ElementTree import fromstring
    except ImportError as exc:
        raise ValueError("XML profile requires optional evtx extra") from exc
    if len(xml) > 65536:
        raise ValueError("xml_record_too_large")
    root = fromstring(xml, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    if root.tag != "{" + NS["e"] + "}Event":
        raise ValueError("unsupported_xml_namespace")
    for query in (
        "e:System",
        "e:EventData",
        "e:System/e:Provider",
        "e:System/e:EventID",
        "e:System/e:Computer",
        "e:System/e:TimeCreated",
    ):
        if len(root.findall(query, NS)) != 1:
            raise ValueError("missing_or_duplicate_xml_metadata")
    fields: dict[str, str | None] = {}
    for element in root.findall("e:EventData/e:Data", NS):
        name = element.get("Name")
        if not name or name in fields:
            raise ValueError("duplicate_or_missing_xml_field")
        fields[name] = element.text
    return root, fields


def map_windows_xml(xml: bytes) -> RawEvent:
    root, fields = _xml_parts(xml)
    provider = root.find("e:System/e:Provider", NS)
    if provider is None or provider.get("Name") != "Microsoft-Windows-Security-Auditing":
        raise ValueError("unsupported_provider")
    code_text = root.findtext("e:System/e:EventID", namespaces=NS)
    if code_text not in ("4624", "4625", "4688"):
        raise ValueError("unsupported_event_code")
    created = root.find("e:System/e:TimeCreated", NS)
    if created is None:
        raise ValueError("missing_timestamp")
    prefix = "Subject" if code_text == "4688" else "Target"
    process = fields.get("NewProcessName") if code_text == "4688" else None
    return RawEvent.model_validate(
        {
            "event_code": int(code_text),
            "timestamp": created.get("SystemTime"),
            "host": _text(root.findtext("e:System/e:Computer", namespaces=NS)),
            "user": _principal(fields.get(prefix + "DomainName"), fields.get(prefix + "UserName")),
            "process": ntpath.basename(_text(process)) if code_text == "4688" else None,
        }
    )


def mapping_supported(source: bytes, raw: RawEvent, kind: str) -> bool:
    """Independent field reconstruction; never calls either producer mapping function."""
    try:
        if kind == "lanl_jsonl":
            data = json.loads(source, object_pairs_hook=unique_fields)
            code = data["EventID"]
            seconds = data["Time"]
            host = data.get("LogHost", data.get("Computer"))
            user = data["DomainName"] + "\\" + data["UserName"]
            process = data.get("ProcessName") if code == 4688 else None
            correct_time = raw.timestamp == ORIGIN + timedelta(seconds=seconds)
            correct_message = raw.message == ORIGIN_WARNING
            consistent = (
                code in (4624, 4625, 4688)
                and type(seconds) is int
                and ("Computer" not in data or data["Computer"] == host)
                and ("LogHost" not in data or data["LogHost"] == host)
            )
        elif kind == "windows_xml":
            root, fields = _xml_parts(source)
            provider = root.find("e:System/e:Provider", NS)
            created = root.find("e:System/e:TimeCreated", NS)
            if provider is None or created is None:
                return False
            code = int(root.findtext("e:System/e:EventID", namespaces=NS))
            host = root.findtext("e:System/e:Computer", namespaces=NS)
            prefix = "Subject" if code == 4688 else "Target"
            user = str(fields[prefix + "DomainName"]) + "\\" + str(fields[prefix + "UserName"])
            process = ntpath.basename(str(fields["NewProcessName"])) if code == 4688 else None
            timestamp = str(created.get("SystemTime"))
            correct_time = raw.timestamp == datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            correct_message = raw.message == ""
            consistent = provider.get("Name") == "Microsoft-Windows-Security-Auditing" and code in (
                4624,
                4625,
                4688,
            )
        else:
            return False
        return bool(
            consistent
            and correct_time
            and correct_message
            and raw.event_code == code
            and raw.host == host
            and raw.user == user
            and raw.process == process
            and all(v is None for v in (raw.src_ip, raw.dst_ip, raw.src_port, raw.dst_port))
        )
    except (ValueError, KeyError, TypeError, OverflowError):
        return False


def decompress_prefix(content: bytes) -> tuple[bytes, bool]:
    if len(content) > MAX_BYTES:
        raise ValueError("compressed_byte_limit")
    decompressor = bz2.BZ2Decompressor()
    result = decompressor.decompress(content, max_length=MAX_BYTES + 1)
    if len(result) > MAX_BYTES:
        raise ValueError("decompressed_byte_limit")
    if decompressor.eof and decompressor.unused_data:
        raise ValueError("unexpected_trailing_compressed_data")
    return result, decompressor.eof


def convert_source(
    content: bytes, kind: Literal["lanl_jsonl", "windows_xml"], *, complete: bool
) -> tuple[bytes, dict[str, Any]]:
    if not content or len(content) > MAX_BYTES:
        raise ValueError("source_byte_limit_or_empty")
    candidates: list[tuple[int, int | None, bytes]]
    if kind == "lanl_jsonl":
        records = content.splitlines(keepends=True)
        if not complete and records and not records[-1].endswith(b"\n"):
            records.pop()
        candidates = [(i, None, line) for i, line in enumerate(records, 1)]
    else:
        if b"<!DOCTYPE" in content or b"<!ENTITY" in content:
            raise ValueError("xml_declarations_forbidden")
        matches = list(re.finditer(rb"<Event(?:\s[^>]*)?>.*?</Event>", content, re.DOTALL))
        candidates = [(i, match.start(), match.group()) for i, match in enumerate(matches, 1)]
        if len(re.findall(rb"<Event(?:\s|>)", content)) != len(matches):
            raise ValueError("incomplete_xml_record")
    rejections: Counter[str] = Counter()
    accepted: list[bytes] = []
    lineage = []
    for ordinal, offset, source in candidates[:MAX_ROWS]:
        try:
            raw = (
                map_lanl(json.loads(source, object_pairs_hook=unique_fields))
                if kind == "lanl_jsonl"
                else map_windows_xml(source)
            )
        except (ValueError, TypeError) as exc:
            reason = (
                str(exc)
                if str(exc)
                in {
                    "unsupported_event_code",
                    "unknown_lanl_field",
                    "invalid_relative_time",
                    "missing_or_conflicting_host",
                    "missing_identity_or_process",
                    "ambiguous_principal_namespace",
                    "invalid_text",
                    "conflicting_auth_status",
                    "invalid_auth_status",
                    "unsupported_provider",
                }
                else "invalid_source_record"
            )
            rejections[reason] += 1
            continue
        if not mapping_supported(source, raw, kind):
            raise ValueError("independent_mapping_discrepancy")
        encoded = (raw.model_dump_json() + "\n").encode()
        accepted.append(encoded)
        entry: dict[str, Any] = {
            "derived_row": len(accepted),
            "source_ordinal": ordinal,
            "source_byte_offset": offset,
            "source_record_sha256": digest(source),
            "derived_record_sha256": digest(encoded),
            "event_code": raw.event_code,
        }
        if kind == "lanl_jsonl":
            entry["source_relative_seconds"] = json.loads(source)["Time"]
        lineage.append(entry)
    derived = b"".join(accepted)
    if len(derived) > 1048576:
        raise ValueError("derived_import_byte_limit")
    return derived, {
        "schema_version": "public-interop-1.0",
        "partition": "development",
        "research_validity": "interoperability_only",
        "gold_labels": None,
        "source_format": kind,
        "source_sha256": digest(content),
        "source_complete": complete,
        "source_records_available": len(candidates),
        "source_records_examined": min(len(candidates), MAX_ROWS),
        "row_cap_reached": len(candidates) > MAX_ROWS,
        "accepted": len(accepted),
        "rejected": dict(rejections),
        "derived_sha256": digest(derived),
        "independent_mapping_checks": len(accepted),
        "independent_mapping_discrepancies": 0,
        "lineage": lineage,
        "calendar_time_known": kind == "windows_xml",
        "runtime_admissible": kind == "windows_xml",
        "time_interpretation": "recorded_source_timestamp"
        if kind == "windows_xml"
        else {
            "source_field": "Time",
            "unit": "seconds",
            "artificial_origin": ORIGIN.isoformat(),
            "warning": ORIGIN_WARNING,
        },
        "omitted": "Source/destination names, IPs, ports, commands and unrelated event fields",
    }
