import pytest

from app import catalog, overlay, profiles


def test_catalog_scans_upstream():
    cats = catalog.scan()
    names = [c.dirname for c in cats]
    assert "1_process_creation" in names
    assert len(cats) >= 20
    pc = next(c for c in cats if c.dirname == "1_process_creation")
    assert pc.event_ids == ["1"]
    assert pc.include_count > 10 and pc.exclude_count > 5
    m = next(m for m in pc.modules if m.filename == "include_clear_windows_event_logs.xml")
    assert m.source == "upstream" and m.kind == "include" and "ProcessCreate" in m.event_types


def test_overlay_shadow_and_revert():
    rel = "1_process_creation/include_clear_windows_event_logs.xml"
    original = overlay.read_text(rel)
    assert overlay.source_of(rel) == "upstream"
    overlay.write_text(rel, original.replace("wevtutil.exe", "example.exe"))
    assert overlay.source_of(rel) == "edited"
    assert "example.exe" in overlay.read_text(rel)
    assert catalog.get_module(rel).source == "edited"
    overlay.revert(rel)
    assert overlay.source_of(rel) == "upstream"
    assert overlay.read_text(rel) == original


def test_new_and_duplicate_module():
    rel = overlay.new_module("22_dns_query", "exclude", "Vores DNS", "DnsQuery")
    assert rel == "22_dns_query/exclude_vores_dns.xml"
    assert overlay.source_of(rel) == "custom"
    assert rel in catalog.module_rels("22_dns_query")
    dup = overlay.duplicate(rel, "kopi")
    assert dup == "22_dns_query/exclude_kopi.xml"
    with pytest.raises(FileExistsError):
        overlay.duplicate(rel, "kopi")
    with pytest.raises(ValueError):
        overlay.read_text("../etc/passwd")


def test_profile_crud_and_lists():
    p = profiles.create("Test Profil", select_all=True)
    assert p.slug == "test-profil"
    assert len(p.modules) == len(catalog.all_module_rels())
    text = profiles.to_include_list(p)
    assert profiles.parse_list(text) == p.modules
    assert profiles.parse_list("# c\n5_process_ended\n") == catalog.module_rels("5_process_ended")
    p.modules = p.modules[:3]
    profiles.save(p)
    assert profiles.load("test-profil").modules == p.modules
