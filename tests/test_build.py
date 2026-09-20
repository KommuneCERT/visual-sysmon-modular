import re

from app import builder, catalog, overlay, profiles

FINDINGS_TEXT = """merged
  [SYS205] field is unsupported by the target Sysmon binary
  ↳ FileCreate.User requires Sysmon 14
  [SYS204] event is unsupported by the target Sysmon binary ×8
  ↳ ProcessTampering requires Sysmon 13
1_process_creation/x.xml
  [SYS106] 1_process_creation/x.xml:5: unknown condition operator
  ↳ Bogus condition=foo

SUMMARY 1 file(s) · 3 errors · 2 warnings
"""


def test_parse_findings():
    f = builder.parse_findings(FINDINGS_TEXT)
    assert [x.code for x in f] == ["SYS205", "SYS204", "SYS106"]
    assert f[1].count == 8 and f[1].severity == "warning" and f[1].section == "merged"
    assert f[2].location == "1_process_creation/x.xml:5" and f[2].section == "1_process_creation/x.xml"
    assert f[0].details == ["FileCreate.User requires Sysmon 14"]
    assert builder.summarize(f)["warning"] == 10


def test_validate_text_reports_errors():
    bad = '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="x" groupRelation="or"><ProcessCreate onmatch="include"><Bogus condition="is">a</Bogus></ProcessCreate></RuleGroup></EventFiltering></Sysmon>'
    findings, code = builder.validate_text(bad, "15")
    assert code != 0
    assert any(f.code == "SYS202" and f.severity == "error" for f in findings)
    good = overlay.read_text("1_process_creation/include_clear_windows_event_logs.xml")
    findings, code = builder.validate_text(good, "15")
    assert code == 0 and not [f for f in findings if f.severity == "error"]


def test_build_small_profile_and_overlay_flow():
    rels = ["5_process_ended/include_security_process_termination.xml",
            "1_process_creation/include_clear_windows_event_logs.xml"]
    p = profiles.create("small", select_all=False)
    p.modules = rels
    profiles.save(p)
    meta = builder.run_build(p)
    assert meta["ok"], meta
    xml = builder.build_path(p.slug, meta["id"], "sysmonconfig.xml").read_text()
    assert "wevtutil.exe" in xml and "<ProcessTerminate" in xml
    assert "<DnsQuery" not in xml
    assert meta["has_coverage"]

    # overlay edit shows up in the next build, and diff sees it
    rel = rels[1]
    overlay.write_text(rel, overlay.read_text(rel).replace("wevtutil.exe", "vsm-test-marker.exe"))
    meta2 = builder.run_build(p)
    assert meta2["ok"]
    xml2 = builder.build_path(p.slug, meta2["id"], "sysmonconfig.xml").read_text()
    assert "vsm-test-marker.exe" in xml2
    assert meta2["has_diff"] and meta2["diff_before"] == meta["id"]
    diff = builder.read_json(p.slug, meta2["id"], "diff.json")
    assert diff["changes"]


def test_full_build_matches_upstream_module_count():
    p = profiles.create("all", select_all=True)
    meta = builder.run_build(p)
    assert meta["ok"], meta["findings"][:3]
    xml = builder.build_path(p.slug, meta["id"], "sysmonconfig.xml").read_text()
    assert xml.startswith('<Sysmon schemaversion="4.90">')
    assert len(re.findall(r"<RuleGroup ", xml)) > 100
