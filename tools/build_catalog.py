#!/usr/bin/env python3
"""Generate the static data files for the site from the sysmon-modular checkout.

Standard library only – runs in GitHub Actions and locally.

  catalog.json   categories + every module's raw XML + template + example lists
  upstream.json  pinned upstream commit / date / url
  fields.json    Sysmon event fields + condition operators (from upstream's Go source)
  attack.json    ATT&CK technique table embedded in upstream's tooling (for autocomplete)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CATEGORY_RE = re.compile(r"^\d+(?:_\d+)*_[a-z0-9_]+$")
CAT_PREFIX_RE = re.compile(r"^(\d+(?:_\d+)*)_(.+)$")

EVENT_IDS = {
    "ProcessCreate": "1", "FileCreateTime": "2", "NetworkConnect": "3", "ProcessTerminate": "5", "DriverLoad": "6",
    "ImageLoad": "7", "CreateRemoteThread": "8", "RawAccessRead": "9", "ProcessAccess": "10", "FileCreate": "11",
    "RegistryEvent": "12/13/14", "FileCreateStreamHash": "15", "PipeEvent": "17/18", "WmiEvent": "19/20/21",
    "DnsQuery": "22", "FileDelete": "23", "ClipboardChange": "24", "ProcessTampering": "25",
    "FileDeleteDetected": "26", "FileBlockExecutable": "27", "FileBlockShredding": "28", "FileExecutableDetected": "29",
}
CONDITIONS = ["is", "is not", "is any", "contains", "contains any", "contains all", "excludes", "excludes any",
              "excludes all", "begin with", "end with", "not begin with", "not end with", "image", "not image",
              "less than", "more than"]
MULTI_VALUE = ["is any", "contains any", "contains all", "excludes any", "excludes all"]


def sort_key(dirname: str) -> tuple[int, str]:
    m = CAT_PREFIX_RE.match(dirname)
    return (int(m.group(1).split("_")[0]) if m else 999, dirname)


def category_meta(dirname: str) -> dict:
    m = CAT_PREFIX_RE.match(dirname)
    ids = m.group(1).split("_") if m else []
    label = m.group(2).replace("_", " ").capitalize() if m else dirname
    return {"dirname": dirname, "event_ids": ids, "label": label}


def read_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln.split("#")[0].strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.split("#")[0].strip()]


def build_presets(rels: list[str], mde_covered: list[str]) -> list[dict]:
    """Module selections that mirror upstream's published configurations
    (.github/workflows/config-build.yml and the MDE augment helper)."""
    release_opts = {"unsupported": "exclude", "preserve_comments": True}
    no_filedelete = [r for r in rels if not r.startswith("23_file_delete/")]
    covered = set(mde_covered)
    return [
        {"id": "balanced", "name": "Balanced", "tagline": "sysmonconfig.xml – upstream's regular starting configuration",
         "use": "Workstations and servers. Start here unless one of the others clearly fits.",
         "description": "Every detection and noise-exclusion module except FileDelete archiving (event 23). Broad telemetry with the volume kept reasonable by the exclusion modules. Servers usually need a few exclusions of your own (backup, RMM, database agents) after the first days – add them as custom exclude modules.",
         "audience": ["workstations", "servers"], "options": release_opts, "modules": no_filedelete},
        {"id": "balanced-filedelete", "name": "Balanced with FileDelete", "tagline": "sysmonconfig-with-filedelete.xml",
         "use": "Servers and high-value hosts where you want deleted files preserved for forensics.",
         "description": "Balanced plus FileDelete (event 23): deleted files are also copied into the Sysmon archive directory on the host. Plan for disk growth; on busy file or database servers prefer Balanced (event 26 still logs deletions without the copy).",
         "audience": ["servers"], "options": release_opts, "modules": list(rels)},
        {"id": "mde-augment", "name": "MDE augment", "tagline": "sysmonconfig-mde-augment.xml",
         "use": "Hosts already onboarded to Microsoft Defender for Endpoint.",
         "description": "Balanced minus the modules whose telemetry MDE already provides (upstream's mde_covered_modules.txt), so Sysmon adds detail where MDE is thin – command lines, DNS, named pipes, registry autostarts – instead of duplicating it.",
         "audience": ["mde"], "options": release_opts, "modules": [r for r in rels if r not in covered]},
        {"id": "excludes-only", "name": "Excludes only", "tagline": "sysmonconfig-excludes-only.xml",
         "use": "Research, lab hosts and short investigations – not a fleet.",
         "description": "Only the noise-exclusion modules: every event type is logged except known noise. Very high volume; load a lighter configuration when the investigation is done.",
         "audience": ["research"], "options": release_opts,
         "modules": [r for r in no_filedelete if r.split("/")[1].startswith("exclude_")]},
    ]


def build_catalog(upstream: Path) -> dict:
    categories, modules = [], []
    for d in sorted((p for p in upstream.iterdir() if p.is_dir() and CATEGORY_RE.match(p.name)), key=lambda p: sort_key(p.name)):
        files = sorted(p for p in d.glob("*.xml") if p.is_file())
        if not files:
            continue  # 0_custom_configuration holds text lists only
        categories.append(category_meta(d.name))
        for f in files:
            modules.append({"rel": f"{d.name}/{f.name}", "xml": f.read_text(encoding="utf-8-sig")})
    template = upstream / "templates" / "sysmon_template.xml"
    examples = {}
    for name in ("example_include_rules.txt", "example_exclude_rules.txt"):
        p = upstream / "0_custom_configuration" / name
        if p.exists():
            examples[name] = p.read_text(encoding="utf-8")
    rels = [m["rel"] for m in modules]
    mde_covered = [r for r in read_list(upstream / "0_custom_configuration" / "mde_covered_modules.txt") if r in set(rels)]
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "categories": categories,
        "modules": modules,
        "template": template.read_text(encoding="utf-8") if template.exists() else "",
        "examples": examples,
        "mde_covered": mde_covered,
        "presets": build_presets(rels, mde_covered),
    }


def build_fields(upstream: Path) -> dict:
    src = (upstream / "tooling" / "internal" / "validate" / "schema.go").read_text()
    events = {m.group(1): m.group(2).split() for m in re.finditer(r'"(\w+)":\s*fields\("([^"]+)"\)', src)}
    min_block = src.split("eventMinSchema")[1].split("}")[0] if "eventMinSchema" in src else ""
    min_schema = dict(re.findall(r'"(\w+)":\s*"([\d.]+)"', min_block))
    return {
        "events": {k: {"fields": v, "event_id": EVENT_IDS.get(k, ""), "min_schema": min_schema.get(k, "4.00")} for k, v in events.items()},
        "conditions": CONDITIONS,
        "multi_value_conditions": MULTI_VALUE,
    }


TECH_RE = re.compile(r'"(T\d{4}(?:\.\d{3})?)":\s*\{Name:\s*"((?:[^"\\]|\\.)*)",\s*Tactics:\s*\[\]string\{([^}]*)\}(.*?)\},?$', re.M)


def build_attack(upstream: Path) -> dict:
    """The Enterprise ATT&CK table upstream embeds (internal/mitre/techniques_gen.go)."""
    src = (upstream / "tooling" / "internal" / "mitre" / "techniques_gen.go").read_text(encoding="utf-8")
    header = {}
    for key, pat in (("bundle_sha256", r"Bundle SHA-256:\s*([0-9a-f]+)"), ("modified", r"modified timestamp:\s*(\S+)")):
        m = re.search(pat, src)
        header[key] = m.group(1) if m else ""
    techniques = []
    for m in TECH_RE.finditer(src):
        tid, name, tactics, rest = m.groups()
        name = name.encode().decode("unicode_escape") if "\\" in name else name
        entry = {"id": tid, "name": name, "tactics": re.findall(r'"([^"]+)"', tactics)}
        if "Revoked: true" in rest:
            entry["revoked"] = True
        if "Deprecated: true" in rest:
            entry["deprecated"] = True
        rm = re.search(r'Replacement:\s*"([^"]+)"', rest)
        if rm:
            entry["replacement"] = rm.group(1)
        techniques.append(entry)
    by_id = {t["id"]: t for t in techniques}
    for t in techniques:   # "Parent: Sub" display name for sub-techniques
        if "." in t["id"]:
            parent = by_id.get(t["id"].split(".")[0])
            t["full"] = f"{parent['name']}: {t['name']}" if parent else t["name"]
    return {**header, "count": len(techniques), "techniques": techniques}


def build_upstream(upstream: Path) -> dict:
    def git(*args: str) -> str:
        try:
            return subprocess.run(["git", "-C", str(upstream), *args], capture_output=True, text=True, check=True).stdout.strip()
        except (subprocess.CalledProcessError, OSError):
            return ""
    commit = git("rev-parse", "HEAD")
    return {
        "commit": commit,
        "short": commit[:7],
        "date": git("log", "-1", "--format=%cs"),
        "subject": git("log", "-1", "--format=%s"),
        "url": "https://github.com/olafhartong/sysmon-modular",
        "commit_url": f"https://github.com/olafhartong/sysmon-modular/commit/{commit}" if commit else "",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", type=Path, default=Path("vendor/sysmon-modular"))
    ap.add_argument("--out", type=Path, default=Path("site/data"))
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    catalog = build_catalog(a.upstream)
    (a.out / "catalog.json").write_text(json.dumps(catalog, ensure_ascii=False, separators=(",", ":")))
    (a.out / "fields.json").write_text(json.dumps(build_fields(a.upstream), indent=1))
    (a.out / "upstream.json").write_text(json.dumps(build_upstream(a.upstream), indent=1))
    attack = build_attack(a.upstream)
    (a.out / "attack.json").write_text(json.dumps(attack, ensure_ascii=False, separators=(",", ":")))
    print(f"catalog: {len(catalog['categories'])} categories, {len(catalog['modules'])} modules, {attack['count']} ATT&CK techniques → {a.out}")


if __name__ == "__main__":
    main()
