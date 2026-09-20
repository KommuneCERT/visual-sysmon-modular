from app import overlay, profiles


def test_pages_render(client):
    r = client.get("/", follow_redirects=True)
    assert r.status_code == 200 and "Search" in r.text
    assert client.get(f"/p/{profiles.list_profiles()[0].slug}/profile").status_code == 200
    slug = profiles.list_profiles()[0].slug
    r = client.get(f"/p/{slug}/c/1_process_creation")
    assert r.status_code == 200 and "include_clear_windows_event_logs.xml" in r.text
    rel = "1_process_creation/include_clear_windows_event_logs.xml"
    assert client.get(f"/p/{slug}/m/{rel}/edit").status_code == 200
    assert client.get(f"/p/{slug}/m/{rel}/raw").status_code == 200
    assert client.get("/healthz").json()["ok"]


def test_toggle_and_build_via_http(client):
    slug = profiles.list_profiles()[0].slug
    rel = "1_process_creation/include_clear_windows_event_logs.xml"
    r = client.post(f"/p/{slug}/toggle", data={"rel": rel})           # unchecked → off
    assert r.status_code == 200 and 'hx-swap-oob="true"' in r.text
    assert rel not in profiles.load(slug).modules
    r = client.post(f"/p/{slug}/toggle", data={"rel": rel, "on": "true"})
    assert rel in profiles.load(slug).modules

    client.post(f"/p/{slug}/select-all", data={"mode": "none"})
    client.post(f"/p/{slug}/toggle", data={"rel": rel, "on": "true"})
    r = client.post(f"/p/{slug}/build", follow_redirects=True)
    assert r.status_code == 200 and "Download sysmonconfig.xml" in r.text
    build_id = r.url.path.rsplit("/", 1)[-1]
    xml = client.get(f"/p/{slug}/builds/{build_id}/sysmonconfig.xml").text
    assert "wevtutil.exe" in xml


def test_structured_save_and_raw_validation(client):
    slug = profiles.list_profiles()[0].slug
    rel = "22_dns_query/exclude_vsm_test.xml"
    r = client.post(f"/p/{slug}/c/22_dns_query/new", data={"name": "vsm test", "kind": "exclude", "event_type": "DnsQuery"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith(f"/m/{rel}/edit")
    model = {"schemaversion": "4.90", "rulegroups": [{"name": "t", "group_relation": "or", "events": [
        {"event_type": "DnsQuery", "onmatch": "exclude", "conditions": [],
         "rules": [{"name": "", "group_relation": "and", "conditions": [{"field": "QueryName", "condition": "end with", "value": ".example.com", "name": ""}]}]}]}]}
    r = client.post(f"/p/{slug}/m/{rel}/edit", json={"model": model})
    assert r.json()["saved"], r.json()
    assert ".example.com" in overlay.read_text(rel)

    bad = dict(model); bad["rulegroups"][0]["events"][0]["rules"][0]["conditions"][0]["field"] = "Nope"
    r = client.post(f"/p/{slug}/m/{rel}/edit", json={"model": bad})
    assert r.json()["saved"] is False and any(f["code"] == "SYS202" for f in r.json()["findings"])

    r = client.post(f"/p/{slug}/m/{rel}/raw", data={"xml": "<Sysmon><broken"})
    assert r.status_code == 200 and "Not saved" in r.text
    r = client.post(f"/p/{slug}/m/{rel}/revert", follow_redirects=False)
    assert r.status_code == 303 and not overlay.exists(rel)
