from app import profiles, search


def test_search_blocks_and_module_hits():
    p = profiles.create("s", select_all=True)
    r = search.search(p, q="wevtutil")
    assert r.total >= 1 and all(h.block in ("rule", "condition") for h in r.hits)
    hit = next(h for h in r.hits if h.rel.endswith("include_clear_windows_event_logs.xml"))
    assert hit.event_type == "ProcessCreate" and hit.onmatch == "include" and "wevtutil.exe" in hit.xml
    assert hit.techniques and hit.techniques[0][0] == "T1685.005"

    # a term that only matches the module path yields one whole-module hit, not one per rule
    r = search.search(p, q="lsass_noise")
    assert r.total == 1 and r.hits[0].block == "module" and "<Sysmon" in r.hits[0].xml

    r = search.search(p, q="lsass", kind="include", category="10_process_access")
    assert r.hits and all(h.kind == "include" and h.category == "10_process_access" for h in r.hits)

    r = search.search(p, q="", kind="exclude", category="22_dns_query")
    assert r.total > 0 and all(h.onmatch == "exclude" for h in r.hits if h.block != "module")

    p.modules = []
    profiles.save(p)
    assert search.search(p, q="wevtutil").total == 0
    assert search.search(p, q="wevtutil", scope="all").total >= 1


def test_search_endpoint(client):
    slug = profiles.list_profiles()[0].slug
    r = client.get(f"/p/{slug}/search?q=wevtutil")
    assert r.status_code == 200 and 'class="vsm-hit' in r.text and 'data-mark="wevtutil"' in r.text
    r = client.get(f"/p/{slug}/?q=wevtutil")
    assert r.status_code == 200 and "hits" in r.text
