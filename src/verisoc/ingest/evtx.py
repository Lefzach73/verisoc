"""Optional bounded native Windows Security log conversion; never executes event content."""

import importlib
import json
import ntpath
from collections import Counter
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import fromstring

from verisoc.core.models import RawEvent
from verisoc.core.provenance import digest
from verisoc.ingest.importer import MAX_BYTES

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def windows_xml_record(xml: str) -> tuple[RawEvent | None, str]:
    if len(xml.encode()) > 65536:
        raise ValueError("XML record too large")
    root = fromstring(xml, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    provider = root.find("e:System/e:Provider", NS)
    code_text = root.findtext("e:System/e:EventID", namespaces=NS)
    if provider is None or provider.get("Name") != "Microsoft-Windows-Security-Auditing":
        return None, "unsupported_provider"
    if code_text not in ("4624", "4625", "4688"):
        return None, "unsupported_event_code"
    fields: dict[str, str | None] = {}
    for element in root.findall("e:EventData/e:Data", NS):
        name = element.get("Name")
        if name is not None:
            if name in fields:
                raise ValueError("Duplicate Windows event field")
            fields[name] = element.text if element.text not in (None, "", "-") else None
    created = root.find("e:System/e:TimeCreated", NS)
    if created is None:
        raise ValueError("Missing Windows event timestamp")
    code = int(code_text)
    process = fields.get("NewProcessName") if code == 4688 else None
    # Retain a basename only; user directories/command lines are not model context.
    if process:
        process = ntpath.basename(process)
    port = fields.get("IpPort")
    raw = RawEvent.model_validate(
        dict(
            event_code=code,
            timestamp=created.get("SystemTime"),
            host=root.findtext("e:System/e:Computer", namespaces=NS),
            user=fields.get("SubjectUserName") if code == 4688 else fields.get("TargetUserName"),
            process=process,
            src_ip=fields.get("IpAddress"),
            src_port=int(port) if port else None,
        )
    )
    return raw, root.findtext("e:System/e:EventRecordID", default="unknown", namespaces=NS)


def convert_evtx(source: Path, destination: Path) -> Path:
    if source.stat().st_size > MAX_BYTES:
        raise ValueError("EVTX sample exceeds 1 MiB research conversion limit")
    if destination.exists() or destination.with_suffix(".provenance.json").exists():
        raise FileExistsError("Refusing to overwrite conversion")
    try:
        library = importlib.import_module("Evtx.Evtx")
    except ImportError as exc:
        raise ValueError("Install optional extra: uv sync --extra evtx") from exc
    rows: list[str] = []
    mapping: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    output_size = 0
    with library.Evtx(str(source)) as log:
        for index, record in enumerate(log.records(), 1):
            if index > 5000:
                raise ValueError("EVTX record count exceeded")
            raw, original_id = windows_xml_record(record.xml())
            if raw is None:
                skipped[original_id] += 1
                continue
            line = raw.model_dump_json() + "\n"
            output_size += len(line.encode())
            if output_size > MAX_BYTES:
                raise ValueError("Converted JSONL exceeds import limit")
            rows.append(line)
            mapping.append(
                {
                    "jsonl_row": len(rows),
                    "evtx_record_ordinal": index,
                    "windows_record_id": original_id,
                    "event_code": raw.event_code,
                }
            )
    if not rows:
        raise ValueError("No supported Windows Security records")
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(rows).encode()
    provenance = {
        "mapping_version": "windows-security-1.0",
        "source_sha256": digest(source.read_bytes()),
        "derived_sha256": digest(content),
        "accepted_records": len(rows),
        "skipped": dict(skipped),
        "mapping": mapping,
        "omitted": "Other EventData fields and raw paths are not admitted",
        "license_note": (
            "Derived data retain source licensing; keep external raw/derived files outside Git."
        ),
    }
    with destination.open("xb") as handle:
        handle.write(content)
    with destination.with_suffix(".provenance.json").open("x") as handle:
        json.dump(provenance, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return destination
