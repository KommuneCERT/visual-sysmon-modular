#!/usr/bin/env python3
"""Generate the static data files for the site from the sysmon-modular checkout.

Standard library only – runs in GitHub Actions and locally.

  catalog.json   categories + every module's raw XML + template + example lists
  upstream.json  pinned upstream commit / date / url
  fields.json    Sysmon event fields + condition operators (from upstream's Go source)
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
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "categories": categories,
        "modules": modules,
        "template": template.read_text(encoding="utf-8") if template.exists() else "",
        "examples": examples,
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
    print(f"catalog: {len(catalog['categories'])} categories, {len(catalog['modules'])} modules → {a.out}")


if __name__ == "__main__":
    main()
