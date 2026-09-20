from app import sysmon_xml

SAMPLE = """<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="Mission-important Windows event log clearing" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">bare.exe</Image>
        <Rule name="technique_id=T1685.005,technique_name=Clear Windows Event Logs" groupRelation="and">
          <OriginalFileName condition="is">wevtutil.exe</OriginalFileName>
          <CommandLine condition="contains any"> cl ;clear-log</CommandLine>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""


def test_parse_roundtrip():
    mod = sysmon_xml.parse(SAMPLE)
    assert mod.schemaversion == "4.90"
    rg = mod.rulegroups[0]
    assert rg.name.startswith("Mission")
    ev = rg.events[0]
    assert ev.event_type == "ProcessCreate" and ev.onmatch == "include"
    assert [c.field for c in ev.conditions] == ["Image"]
    assert ev.rules[0].conditions[1].value == "cl ;clear-log"
    assert mod.techniques == [("T1685.005", "Clear Windows Event Logs")]
    assert mod.rule_count == 2

    xml = sysmon_xml.to_xml(mod)
    again = sysmon_xml.parse(xml)
    assert again.to_dict() == mod.to_dict()
    assert 'condition="contains any"' in xml


def test_dict_roundtrip_and_empty_module():
    mod = sysmon_xml.empty_module("DnsQuery", "exclude", "My group")
    d = mod.to_dict()
    back = sysmon_xml.Module.from_dict(d)
    assert back.rulegroups[0].events[0].event_type == "DnsQuery"
    xml = sysmon_xml.to_xml(back)
    assert '<DnsQuery onmatch="exclude"/>' in xml


def test_schema_has_all_events():
    assert "ProcessCreate" in sysmon_xml.SCHEMA["events"]
    assert "Image" in sysmon_xml.SCHEMA["events"]["ProcessCreate"]["fields"]
    assert "contains any" in sysmon_xml.CONDITIONS
