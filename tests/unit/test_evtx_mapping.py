import pytest
from defusedxml.common import DefusedXmlException

from verisoc.ingest.evtx import windows_xml_record

XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>
<TimeCreated SystemTime="2026-01-01T00:00:00Z"/><EventRecordID>42</EventRecordID>
<Computer>lab</Computer></System>
<EventData><Data Name="TargetUserName">user</Data><Data Name="IpAddress">192.0.2.4</Data>
<Data Name="IpPort">1234</Data></EventData></Event>"""


def test_windows_fields_are_mapped_and_unknown_providers_are_skipped():
    raw, rid = windows_xml_record(XML)
    assert rid == "42" and raw.event_code == 4625 and str(raw.src_ip) == "192.0.2.4"
    assert windows_xml_record(XML.replace("Security-Auditing", "Something-Else")) == (
        None,
        "unsupported_provider",
    )
    assert windows_xml_record(XML.replace("4625", "9999")) == (None, "unsupported_event_code")


def test_windows_xml_rejects_entities_duplicate_fields_and_missing_time():
    for text in (
        '<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///not-read">]>' + XML,
        XML.replace("</EventData>", '<Data Name="IpPort">22</Data></EventData>'),
        XML.replace('<TimeCreated SystemTime="2026-01-01T00:00:00Z"/>', ""),
    ):
        with pytest.raises((ValueError, DefusedXmlException)):
            windows_xml_record(text)


def test_process_mapping_omits_user_directory_path():
    xml = XML.replace("4625", "4688").replace(
        "</EventData>",
        '<Data Name="NewProcessName">C:\\Users\\private\\tool.exe</Data></EventData>',
    )
    raw, _ = windows_xml_record(xml)
    assert raw.process == "tool.exe"
