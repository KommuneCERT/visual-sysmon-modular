"""Drive the upstream sysmon-modular CLI: merge, validate, coverage, diff.

A build composes a temporary tree (upstream + overlay on top), writes the
profile as an include list and calls ``sysmon-modular merge``. Every build is
kept under ``/data/builds/<profile>/<timestamp>/`` with its artifacts.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config, overlay
from .profiles import Profile, to_include_list

# Severity per finding code – the CLI prints codes but not severities.
SEVERITY: dict[str, str] = {
    "XML001": "error", "SYS001": "error", "SYS002": "error", "SYS003": "warning", "SYS004": "warning",
    "SYS005": "error", "SYS101": "error", "SYS102": "error", "SYS103": "error", "SYS104": "error",
    "SYS105": "error", "SYS106": "warning", "SYS107": "error", "SYS201": "warning", "SYS202": "error",
    "SYS203": "warning", "SYS204": "warning", "SYS205": "warning", "SYS206": "warning",
    "ANL001": "recommendation", "ANL002": "recommendation", "ANL003": "performance", "ANL004": "performance",
    "ANL005": "warning",
}
SEVERITY_ORDER = ["error", "warning", "performance", "recommendation", "info"]

FINDING_RE = re.compile(r"^\s*\[([A-Z_0-9]+)\]\s*(?:(?P<loc>[^:]+?:\d+|line \d+):\s*)?(?P<msg>.*?)(?:\s*×(?P<count>\d+))?\s*$")
DETAIL_RE = re.compile(r"^\s*↳\s?(.*)$")


def severity_of(code: str) -> str:
    if code in SEVERITY:
        return SEVERITY[code]
    if code.startswith("MITRE_"):
        return "error"
    if code.startswith("ANL"):
        return "recommendation"
    return "info"


@dataclass
class Finding:
    code: str
    message: str
    severity: str
    location: str = ""
    section: str = ""
    count: int = 1
    details: list[str] = field(default_factory=list)


def parse_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    section = ""
    for line in text.splitlines():
        if not line.strip() or line.startswith("SUMMARY") or line.startswith("validation "):
            continue
        m = FINDING_RE.match(line)
        if m and line.lstrip().startswith("["):
            code = m.group(1)
            findings.append(Finding(
                code=code, message=m.group("msg"), severity=severity_of(code),
                location=m.group("loc") or "", section=section, count=int(m.group("count") or 1),
            ))
            continue
        d = DETAIL_RE.match(line)
        if d and findings:
            findings[-1].details.append(d.group(1))
            continue
        if not line.startswith(" "):
            section = line.strip()   # e.g. "merged" or a file name
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + f.count
    return out


# ── CLI wrapper ──────────────────────────────────────────────────────────────
def run_cli(args: list[str], cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run([config.CLI_BIN, *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)


def cli_version() -> str:
    try:
        return run_cli(["version"]).stdout.strip()
    except OSError as exc:
        return f"unavailable ({exc})"


def compose_tree(dest: Path) -> Path:
    """Upstream numbered dirs + templates, then overlay files on top."""
    for src in config.UPSTREAM_DIR.iterdir():
        if src.is_dir() and (overlay.CATEGORY_RE.match(src.name) or src.name == "templates"):
            shutil.copytree(src, dest / src.name, dirs_exist_ok=True)
    if config.OVERLAY_DIR.exists():
        for p in config.OVERLAY_DIR.glob("*/*.xml"):
            target = dest / p.parent.name / p.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
    return dest


# ── validate a single module text ───────────────────────────────────────────
def validate_text(xml_text: str, sysmon_version: str | None = None) -> tuple[list[Finding], int]:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "module.xml"
        p.write_text(xml_text, encoding="utf-8")
        args = ["validate", "--path", str(p)]
        if sysmon_version:
            args += ["--sysmon-version", sysmon_version]
        r = run_cli(args)
    return parse_findings(r.stdout + "\n" + r.stderr), r.returncode


# ── build ────────────────────────────────────────────────────────────────────
def profile_build_dir(slug: str) -> Path:
    return config.BUILDS_DIR / slug


def list_builds(slug: str) -> list[dict]:
    d = profile_build_dir(slug)
    if not d.exists():
        return []
    out = []
    for b in sorted(d.iterdir(), reverse=True):
        meta = b / "meta.json"
        if meta.exists():
            out.append(json.loads(meta.read_text()))
    return out


def load_build(slug: str, build_id: str) -> dict | None:
    if not re.match(r"^[0-9T\-]+$", build_id):
        return None
    meta = profile_build_dir(slug) / build_id / "meta.json"
    return json.loads(meta.read_text()) if meta.exists() else None


def build_path(slug: str, build_id: str, name: str) -> Path:
    return profile_build_dir(slug) / build_id / name


def run_build(profile: Profile) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    build_id, n = stamp, 1
    while (profile_build_dir(profile.slug) / build_id).exists():   # two builds in the same second
        n += 1
        build_id = f"{stamp}-{n}"
    out_dir = profile_build_dir(profile.slug) / build_id
    out_dir.mkdir(parents=True, exist_ok=True)
    previous = list_builds(profile.slug)
    prev_ok = next((b for b in previous if b.get("ok") and b["id"] != build_id), None)

    include_list = out_dir / "include_rules.txt"
    include_list.write_text(to_include_list(profile))
    (out_dir / "profile.json").write_text(profile.model_dump_json(indent=2))
    output = out_dir / "sysmonconfig.xml"

    with tempfile.TemporaryDirectory() as td:
        base = compose_tree(Path(td))
        args = [
            "merge", "--base-path", str(base), "--include-list", str(include_list),
            "--sysmon-version", profile.sysmon_version, "--unsupported", profile.unsupported,
            "--output", str(output),
        ]
        if profile.preserve_comments:
            args.append("--preserve-comments")
        if profile.force_grouprelation_or:
            args.append("--force-grouprelation-or")
        if profile.analyze:
            args.append("--analyze")
        if not profile.modules:
            args += ["--validate=false"]
        r = run_cli(args, cwd=base)
        log = f"$ sysmon-modular {' '.join(args)}\n\n{r.stdout}{r.stderr}"
        (out_dir / "build.log").write_text(log)
        findings = parse_findings(r.stdout + "\n" + r.stderr)

        coverage: dict | None = None
        if r.returncode == 0 and output.exists():
            c = run_cli(["coverage", "--base-path", str(base), "--include-list", str(include_list), "--format", "json"], cwd=base)
            if c.returncode == 0:
                try:
                    coverage = json.loads(c.stdout)
                    (out_dir / "coverage.json").write_text(c.stdout)
                except json.JSONDecodeError:
                    coverage = None

    diff: dict | None = None
    if r.returncode == 0 and output.exists() and prev_ok:
        before = profile_build_dir(profile.slug) / prev_ok["id"] / "sysmonconfig.xml"
        if before.exists():
            d = run_cli(["diff", "--before", str(before), "--after", str(output), "--format", "json"])
            if d.returncode == 0:
                try:
                    diff = json.loads(d.stdout)
                    diff["before_id"] = prev_ok["id"]
                    (out_dir / "diff.json").write_text(json.dumps(diff))
                except json.JSONDecodeError:
                    diff = None

    meta = {
        "id": build_id,
        "profile": profile.slug,
        "profile_name": profile.name,
        "sysmon_version": profile.sysmon_version,
        "schemaversion": config.SCHEMA_FOR_VERSION.get(profile.sysmon_version, ""),
        "module_count": len(profile.modules),
        "ok": r.returncode == 0 and output.exists(),
        "exit_code": r.returncode,
        "summary": summarize(findings),
        "findings": [asdict(f) for f in findings],
        "has_coverage": coverage is not None,
        "has_diff": diff is not None,
        "diff_before": prev_ok["id"] if diff else None,
        "output_size": output.stat().st_size if output.exists() else 0,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    return meta


def read_json(slug: str, build_id: str, name: str) -> dict | None:
    p = build_path(slug, build_id, name)
    return json.loads(p.read_text()) if p.exists() else None


def diff_builds(slug: str, before_id: str, after_id: str) -> tuple[dict | None, str]:
    before = build_path(slug, before_id, "sysmonconfig.xml")
    after = build_path(slug, after_id, "sysmonconfig.xml")
    if not (before.exists() and after.exists()):
        return None, "one of the builds has no sysmonconfig.xml"
    d = run_cli(["diff", "--before", str(before), "--after", str(after), "--format", "json"])
    if d.returncode != 0:
        return None, d.stderr or d.stdout
    try:
        return json.loads(d.stdout), ""
    except json.JSONDecodeError:
        return None, d.stdout
