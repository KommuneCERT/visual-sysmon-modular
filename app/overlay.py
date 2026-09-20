"""Copy-on-write layer on top of the read-only upstream tree.

Module paths are always *relative* (e.g. ``1_process_creation/include_foo.xml``).
Overlay files shadow upstream files with the same relative path; files that
only exist in the overlay are custom modules.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import config
from .sysmon_xml import empty_module, to_xml

CATEGORY_RE = re.compile(r"^\d+(?:_\d+)*_[a-z0-9_]+$")
MODULE_RE = re.compile(r"^(include|exclude)_[A-Za-z0-9._-]+\.xml$")


def _safe_rel(rel: str) -> str:
    rel = rel.strip().replace("\\", "/").lstrip("/")
    parts = rel.split("/")
    if len(parts) != 2 or not CATEGORY_RE.match(parts[0]) or not parts[1].endswith(".xml") or ".." in rel:
        raise ValueError(f"invalid module path: {rel!r}")
    return rel


def upstream_path(rel: str) -> Path:
    return config.UPSTREAM_DIR / _safe_rel(rel)


def overlay_path(rel: str) -> Path:
    return config.OVERLAY_DIR / _safe_rel(rel)


def resolve(rel: str) -> Path:
    """Effective file for a module: overlay if present, else upstream."""
    o = overlay_path(rel)
    if o.exists():
        return o
    u = upstream_path(rel)
    if u.exists():
        return u
    raise FileNotFoundError(rel)


def exists(rel: str) -> bool:
    try:
        resolve(rel)
        return True
    except (FileNotFoundError, ValueError):
        return False


def is_overlay(rel: str) -> bool:
    return overlay_path(rel).exists()


def in_upstream(rel: str) -> bool:
    return upstream_path(rel).exists()


def source_of(rel: str) -> str:
    """'upstream' | 'edited' (overlay shadows upstream) | 'custom' (overlay only)."""
    if is_overlay(rel):
        return "edited" if in_upstream(rel) else "custom"
    return "upstream"


def read_text(rel: str) -> str:
    return resolve(rel).read_text(encoding="utf-8")


def write_text(rel: str, text: str) -> Path:
    p = overlay_path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def revert(rel: str) -> None:
    """Drop the overlay copy. For custom modules this deletes the module."""
    p = overlay_path(rel)
    if p.exists():
        p.unlink()


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    if not s:
        raise ValueError("name is empty")
    return s


def new_module(category: str, kind: str, name: str, event_type: str, schemaversion: str = "4.90") -> str:
    if kind not in ("include", "exclude"):
        raise ValueError("kind must be include or exclude")
    rel = f"{category}/{kind}_{slugify(name)}.xml"
    if exists(rel):
        raise FileExistsError(rel)
    write_text(rel, to_xml(empty_module(event_type, kind, name, schemaversion)))
    return rel


def duplicate(rel: str, new_name: str) -> str:
    cat, fname = _safe_rel(rel).split("/")
    kind = "exclude" if fname.startswith("exclude_") else "include"
    new_rel = f"{cat}/{kind}_{slugify(new_name)}.xml"
    if exists(new_rel):
        raise FileExistsError(new_rel)
    write_text(new_rel, read_text(rel))
    return new_rel


def overlay_files() -> list[str]:
    if not config.OVERLAY_DIR.exists():
        return []
    return sorted(
        str(p.relative_to(config.OVERLAY_DIR))
        for p in config.OVERLAY_DIR.glob("*/*.xml")
        if CATEGORY_RE.match(p.parent.name)
    )
