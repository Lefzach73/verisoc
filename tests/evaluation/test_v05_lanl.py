import bz2
import json
import runpy
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from verisoc.core.provenance import digest
from verisoc.evaluation.v05_lanl import (
    MAX_BYTES,
    ORIGIN,
    convert_source,
    decompress_prefix,
    map_lanl,
    map_windows_xml,
    mapping_supported,
)


def record(code=4624):
    return {
        "EventID": code,
        "Time": 2,
        "Computer": "Host1",
        "DomainName": "Domain1",
        "UserName": "User1",
        "Source": "Host2",
        **({"ProcessName": "test.exe"} if code == 4688 else {}),
    }


def xml():
    return b"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>
<Computer>Host1</Computer><TimeCreated SystemTime="2020-01-01T12:00:00Z"/></System>
<EventData><Data Name="SubjectUserName">User1</Data><Data Name="SubjectDomainName">Domain1</Data>
<Data Name="NewProcessName">C:\\Windows\\test.exe</Data></EventData></Event>"""


@pytest.mark.parametrize("code", [4624, 4625, 4688])
def test_lanl_relative_time_scoped_principal_and_no_invented_network(code):
    original = record(code)
    raw = map_lanl(original)
    assert raw.timestamp == ORIGIN + timedelta(seconds=2)
    assert raw.user == "Domain1\\User1"
    assert raw.src_ip is None and raw.dst_ip is None
    assert "not the calendar time" in raw.message
    assert mapping_supported(json.dumps(original).encode(), raw, "lanl_jsonl")
    assert not mapping_supported(
        json.dumps(original).encode(), raw.model_copy(update={"user": "User1"}), "lanl_jsonl"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"Time": True},
        {"Time": -1},
        {"Time": "2"},
        {"Time": 1000000000000},
        {"EventID": 3},
        {"EventID": "4624"},
        {"DomainName": None},
        {"UserName": "A\\B"},
        {"LogHost": "other"},
        {"GoldLabel": "benign"},
        {"Status": "0xc000"},
    ],
)
def test_lanl_rejects_ambiguous_or_unsupported_mapping(mutation):
    with pytest.raises(ValueError):
        map_lanl(record() | mutation)


def test_source_prefix_keeps_explicit_lineage_and_does_not_add_labels():
    source = b"".join(json.dumps(r).encode() + b"\n" for r in (record(), record(4769)))
    derived, manifest = convert_source(source + b'{"incomplete":', "lanl_jsonl", complete=False)
    assert len(derived.splitlines()) == 1
    assert manifest["accepted"] == 1
    assert manifest["rejected"] == {"unsupported_event_code": 1}
    assert manifest["source_complete"] is False
    assert manifest["gold_labels"] is None
    assert manifest["calendar_time_known"] is False
    assert manifest["lineage"][0]["source_relative_seconds"] == 2


def test_duplicate_json_fields_are_rejected_not_silently_resolved():
    source = json.dumps(record()).replace('"Time": 2', '"Time": 2, "Time": 3').encode()
    derived, manifest = convert_source(source, "lanl_jsonl", complete=True)
    assert derived == b""
    assert manifest["rejected"] == {"invalid_source_record": 1}


def test_xml_source_maps_domain_and_independent_oracle_catches_wrong_process():
    pytest.importorskip("defusedxml")
    raw = map_windows_xml(xml())
    assert raw.process == "test.exe" and raw.user == "Domain1\\User1"
    assert mapping_supported(xml(), raw, "windows_xml")
    assert not mapping_supported(
        xml(), raw.model_copy(update={"process": "other.exe"}), "windows_xml"
    )
    derived, manifest = convert_source(xml(), "windows_xml", complete=True)
    assert len(derived.splitlines()) == manifest["independent_mapping_checks"] == 1
    assert manifest["lineage"][0]["source_byte_offset"] == 0


def test_xml_rejects_wrong_provider_duplicate_fields_and_truncated_record():
    pytest.importorskip("defusedxml")
    with pytest.raises(ValueError, match="unsupported_provider"):
        map_windows_xml(xml().replace(b"Microsoft-Windows-Security-Auditing", b"Untrusted"))
    with pytest.raises(ValueError, match="duplicate"):
        map_windows_xml(
            xml().replace(b"</EventData>", b'<Data Name="SubjectUserName">Other</Data></EventData>')
        )
    with pytest.raises(ValueError, match="incomplete"):
        convert_source(xml()[:-8], "windows_xml", complete=False)
    with pytest.raises(ValueError, match="xml_declarations_forbidden"):
        convert_source(
            b'<!DOCTYPE Event [<!ENTITY x "bad">]>' + xml(), "windows_xml", complete=True
        )


def test_compressed_bombs_and_trailing_streams_rejected():
    with pytest.raises(ValueError, match="decompressed_byte_limit"):
        decompress_prefix(bz2.compress(b"A" * (MAX_BYTES + 1)))
    with pytest.raises(ValueError, match="trailing"):
        decompress_prefix(bz2.compress(b"ok") + b"extra")
    source = bz2.compress(json.dumps(record()).encode() + b"\n")
    data, complete = decompress_prefix(source)
    assert complete and b'"Time": 2' in data


def test_independent_checker_is_not_producer(monkeypatch):
    import verisoc.evaluation.v05_lanl as module

    wrong = map_lanl(record()).model_copy(update={"host": "wrong"})
    monkeypatch.setattr(module, "map_lanl", lambda _: wrong)
    with pytest.raises(ValueError, match="independent_mapping_discrepancy"):
        convert_source(json.dumps(record()).encode(), "lanl_jsonl", complete=True)


def test_domain_namespace_cannot_collapse_same_user():
    assert map_lanl(record()).user != map_lanl(record() | {"DomainName": "Other"}).user


def test_non_object_rows_and_empty_process_cannot_produce_admitted_events():
    derived, manifest = convert_source(b"[]\n", "lanl_jsonl", complete=True)
    assert derived == b"" and manifest["accepted"] == 0
    with pytest.raises(ValueError, match="missing_identity_or_process"):
        map_lanl(record(4688) | {"ProcessName": None})


def test_xml_duplicate_system_metadata_cannot_choose_convenient_first_value():
    pytest.importorskip("defusedxml")
    with pytest.raises(ValueError, match="duplicate_xml_metadata"):
        map_windows_xml(xml().replace(b"</System>", b"<Computer>Other</Computer></System>"))


def test_base_lanl_profile_does_not_require_xml_optional_dependency(monkeypatch):
    import builtins

    original = builtins.__import__

    def without_xml(name, *args, **kwargs):
        if name.startswith("defusedxml"):
            raise ImportError("simulated missing optional extra")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_xml)
    assert map_lanl(record()).event_code == 4624
    with pytest.raises(ValueError, match="optional evtx extra"):
        map_windows_xml(xml())


def test_bounded_selection_reports_unexamined_source_rows():
    source = b"".join(json.dumps(record() | {"Time": i}).encode() + b"\n" for i in range(501))
    _, manifest = convert_source(source, "lanl_jsonl", complete=True)
    assert manifest["source_records_available"] == 501
    assert manifest["source_records_examined"] == manifest["accepted"] == 500
    assert manifest["row_cap_reached"] is True


def test_script_blocks_relative_time_before_operational_export_or_runtime(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[2] / "scripts/prepare_lanl_development.py"
    namespace = runpy.run_path(str(script))
    runtime = namespace["main"].__globals__
    cached, raw, out = tmp_path / "cache", tmp_path / "raw", tmp_path / "out"
    cached.mkdir()
    sources = (
        (
            "license-source.txt",
            runtime["LANL_PAGE"],
            b"waived all copyright and related or neighboring rights - TEST FIXTURE ONLY",
        ),
        (
            "source-prefix.bz2",
            runtime["LANL_DATA"],
            bz2.compress(json.dumps(record()).encode() + b"\n"),
        ),
    )
    for name, url, data in sources:
        (cached / name).write_bytes(data)
        (cached / (name + ".receipt.json")).write_text(
            json.dumps(
                {
                    "status": 200,
                    "url": url,
                    "body_sha256": digest(data),
                    "body_bytes": len(data),
                    "headers": {"Content-Length": str(len(data))},
                }
            )
        )

    def forbidden(*args, **kwargs):
        raise AssertionError("Relative-time data reached operational runtime or network")

    for name in ("Database", "import_jsonl", "triage", "fetch"):
        monkeypatch.setitem(runtime, name, forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(script),
            "--source",
            "lanl",
            "--raw",
            str(raw),
            "--out",
            str(out),
            "--offline-from",
            str(cached),
        ],
    )
    assert namespace["main"]() == 2
    summary = json.loads((out / "summary.json").read_text())
    assert summary["blocker"] == "native_relative_time_runtime_support_required"
    assert summary["imported_events"] == 0
    assert not any((out / name).exists() for name in ("events.jsonl", "case.json", "triage.json"))
    preview = json.loads((out / "relative-time-preview.json").read_text())
    assert preview["runtime_admissible"] is False
    assert preview["rows"][0]["relative_seconds"] == 2
    assert "timestamp" not in preview["rows"][0]
