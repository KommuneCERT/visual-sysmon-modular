"""Scan upstream + overlay into categories and modules for the UI."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import config, overlay
from .sysmon_xml import parse_file

_cache: dict[str, tuple[float, "Module"]] = {}

CAT_PREFIX_RE = re.compile(r"^(\d+(?:_\d+)*)_(.+)$")


@dataclass
class Module:
    rel: str
    category: str
    filename: str
    kind: str                     # include | exclude | other
    source: str                   # upstream | edited | custom
    title: str                    # first RuleGroup name or filename
    event_types: list[str] = field(default_factory=list)
    techniques: list[tuple[str, str]] = field(default_factory=list)
    rule_count: int = 0
    error: str = ""


@dataclass
class Category:
    dirname: str
    event_ids: list[str]
    label: str
    modules: list[Module] = field(default_factory=list)

    @property
    def include_count(self) -> int:
        return sum(1 for m in self.modules if m.kind == "include")

    @property
    def exclude_count(self) -> int:
        return sum(1 for m in self.modules if m.kind == "exclude")


def category_label(dirname: str) -> tuple[list[str], str]:
    m = CAT_PREFIX_RE.match(dirname)
    if not m:
        return [], dirname
    ids = m.group(1).split("_")
    label = m.group(2).replace("_", " ").capitalize()
    return ids, label


def filename_title(fname: str) -> str:
    """exclude_adobe_acrobat.xml -> 'Adobe acrobat'"""
    stem = re.sub(r"^(include|exclude)_", "", fname.removesuffix(".xml"))
    return stem.replace("_", " ").replace("-", " ").strip().capitalize() or fname


def _sort_key(dirname: str) -> tuple[int, str]:
    m = CAT_PREFIX_RE.match(dirname)
    return (int(m.group(1).split("_")[0]) if m else 999, dirname)


def parsed_module(rel: str):
    """Parsed sysmon_xml.Module for a module path, cached on file mtime."""
    path = overlay.resolve(rel)
    mtime = path.stat().st_mtime
    cached = _cache.get(str(path))
    if cached and cached[0] == mtime:
        return cached[1]
    parsed = parse_file(path)
    _cache[str(path)] = (mtime, parsed)
    return parsed


def _load_module(rel: str) -> Module:
    cat, fname = rel.split("/")
    path = overlay.resolve(rel)
    kind = "include" if fname.startswith("include_") else "exclude" if fname.startswith("exclude_") else "other"
    mod = Module(rel=rel, category=cat, filename=fname, kind=kind, source=overlay.source_of(rel), title=fname)
    try:
        parsed = parsed_module(rel)
        mod.title = next((rg.name for rg in parsed.rulegroups if rg.name), "") or filename_title(fname)
        mod.event_types = parsed.event_types
        mod.techniques = parsed.techniques
        mod.rule_count = parsed.rule_count
    except Exception as exc:  # broken XML in overlay must not break the page
        mod.error = str(exc)
    return mod


def category_dirs() -> list[str]:
    names = {p.name for p in config.UPSTREAM_DIR.iterdir() if p.is_dir() and overlay.CATEGORY_RE.match(p.name)}
    if config.OVERLAY_DIR.exists():
        names |= {p.name for p in config.OVERLAY_DIR.iterdir() if p.is_dir() and overlay.CATEGORY_RE.match(p.name)}
    return sorted(names, key=_sort_key)


def module_rels(category: str) -> list[str]:
    files: set[str] = set()
    for base in (config.UPSTREAM_DIR / category, config.OVERLAY_DIR / category):
        if base.is_dir():
            files |= {p.name for p in base.glob("*.xml")}
    return [f"{category}/{f}" for f in sorted(files)]


def scan() -> list[Category]:
    cats: list[Category] = []
    for d in category_dirs():
        ids, label = category_label(d)
        cat = Category(dirname=d, event_ids=ids, label=label)
        cat.modules = [_load_module(rel) for rel in module_rels(d)]
        if cat.modules:
            cats.append(cat)
    return cats


def all_module_rels() -> list[str]:
    return [rel for d in category_dirs() for rel in module_rels(d)]


def get_category(dirname: str) -> Category | None:
    return next((c for c in scan() if c.dirname == dirname), None)


def get_module(rel: str) -> Module:
    return _load_module(rel)
