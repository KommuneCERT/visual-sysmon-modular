from app import attack, profiles


COV = {
    "events": [{"name": "ProcessCreate", "include": 3, "exclude": 0, "modules": ["a"]}],
    "techniques": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "modules": ["1_process_creation/a.xml"], "count": 2},
        {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactics": ["execution"], "modules": ["1_process_creation/b.xml"], "count": 5},
        {"id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys", "tactics": ["persistence", "privilege-escalation"], "modules": ["12_13_14_registry_event/c.xml"], "count": 1},
        {"id": "T9999", "name": "Unknown", "tactics": [], "modules": ["x"], "count": 1},
    ],
    "tactics": {"execution": 7, "persistence": 1, "privilege-escalation": 1},
    "include": 9, "exclude": 0,
}


def test_build_matrix_groups_by_tactic_and_nests_subs():
    m = attack.build_matrix(COV)
    tactics = [c["tactic"] for c in m["columns"]]
    assert tactics == ["execution", "persistence", "privilege-escalation", "unmapped"]
    ex = m["columns"][0]["techniques"]
    assert len(ex) == 1 and ex[0]["id"] == "T1059" and ex[0]["direct"]
    assert ex[0]["subs"][0]["id"] == "T1059.001" and ex[0]["total"] == 7 and ex[0]["module_count"] == 2
    pe = m["columns"][2]["techniques"][0]
    assert pe["id"] == "T1547" and not pe["direct"] and pe["name"] == "Boot or Logon Autostart Execution"
    assert m["technique_total"] == 4 and m["parent_total"] == 3 and m["sub_total"] == 2 and m["tactic_total"] == 3


def test_rule_tagging_counts_group_inheritance():
    t = attack.rule_tagging(["1_process_creation/include_clear_windows_event_logs.xml",
                             "5_process_ended/include_security_process_termination.xml"])
    assert t["total"] == t["tagged"] + t["untagged"]
    assert t["tagged"] >= 3          # the event-log module has 3 tagged rules
    assert t["pct"] == 100 and not t["untagged_modules"]


def test_coverage_pages(client):
    slug = profiles.list_profiles()[0].slug
    r = client.get(f"/p/{slug}/coverage")
    assert r.status_code == 200 and "ATT&amp;CK coverage" in r.text and "vsm-tactic-head" in r.text
    r = client.get(f"/p/{slug}/coverage.json")
    assert r.status_code == 200 and r.json()["techniques"]
    r = client.get(f"/p/{slug}/coverage/navigator.json?attack_version=19")
    assert r.status_code == 200 and r.json()["domain"] == "enterprise-attack"
