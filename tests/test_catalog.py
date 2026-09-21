import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_catalog  # noqa: E402

UPSTREAM = ROOT / "vendor" / "sysmon-modular"


def test_catalog_structure(tmp_path):
    cat = build_catalog.build_catalog(UPSTREAM)
    assert len(cat["categories"]) >= 20
    assert cat["categories"][0]["dirname"] == "1_process_creation"
    assert cat["categories"][0]["event_ids"] == ["1"] and cat["categories"][0]["label"] == "Process creation"
    rels = {m["rel"] for m in cat["modules"]}
    assert "1_process_creation/include_clear_windows_event_logs.xml" in rels
    assert len(rels) == len(cat["modules"]) > 400
    assert all("<Sysmon" in m["xml"] for m in cat["modules"])
    assert "<HashAlgorithms>" in cat["template"]
    assert "example_include_rules.txt" in cat["examples"]
    presets = {p["id"]: p for p in cat["presets"]}
    n_all = len(rels)
    n_fd = sum(1 for r in rels if r.startswith("23_file_delete/"))
    assert n_fd > 0
    assert len(presets["balanced"]["modules"]) == n_all - n_fd
    assert len(presets["balanced-filedelete"]["modules"]) == n_all
    assert len(presets["mde-augment"]["modules"]) == n_all - len(cat["mde_covered"]) and len(cat["mde_covered"]) > 100
    assert all(r.split("/")[1].startswith("exclude_") and not r.startswith("23_") for r in presets["excludes-only"]["modules"])
    assert presets["balanced"]["options"] == {"unsupported": "exclude", "preserve_comments": True}


def test_fields_and_upstream():
    f = build_catalog.build_fields(UPSTREAM)
    assert "Image" in f["events"]["ProcessCreate"]["fields"]
    assert f["events"]["ProcessCreate"]["event_id"] == "1"
    assert "contains any" in f["conditions"]
    u = build_catalog.build_upstream(UPSTREAM)
    if shutil.which("git"):
        assert len(u["commit"]) == 40 and u["short"] == u["commit"][:7]
    assert u["url"].startswith("https://github.com/")


def test_attack_table():
    a = build_catalog.build_attack(UPSTREAM)
    assert a["count"] > 800 and len(a["bundle_sha256"]) == 64
    by = {t["id"]: t for t in a["techniques"]}
    assert by["T1003"]["name"] == "OS Credential Dumping" and by["T1003"]["tactics"] == ["credential-access"]
    assert by["T1003.001"]["full"] == "OS Credential Dumping: LSASS Memory"
    assert by["T1002"].get("revoked") and by["T1002"]["replacement"] == "T1560"
    assert sum(1 for t in a["techniques"] if t.get("revoked")) > 100


def test_cli_writes_files(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "tools" / "build_catalog.py"), "--upstream", str(UPSTREAM), "--out", str(tmp_path)], check=True)
    for name in ("catalog.json", "fields.json", "upstream.json", "attack.json"):
        json.loads((tmp_path / name).read_text())
