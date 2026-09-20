"""Free-text search across the modules of a profile, returning the matching
XML blocks (a <Rule> or a bare condition) with their context."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import catalog, overlay, sysmon_xml
from .profiles import Profile

MAX_HITS = 150


@dataclass
class Hit:
    rel: str
    category: str
    kind: str            # include | exclude | other
    source: str          # upstream | edited | custom
    selected: bool
    group_name: str
    group_relation: str
    event_type: str
    onmatch: str
    block: str           # rule | condition | module
    name: str
    xml: str
    techniques: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Result:
    hits: list[Hit]
    total: int
    modules_scanned: int
    modules_hit: int
    terms: list[str]
    truncated: bool


def _kind(rel: str) -> str:
    f = rel.split("/")[1]
    return "include" if f.startswith("include_") else "exclude" if f.startswith("exclude_") else "other"


def _matches(terms: list[str], *parts: str) -> bool:
    hay = " ".join(p for p in parts if p).lower()
    return all(t in hay for t in terms)


def _content_hit(terms: list[str], ctx: tuple, content: str) -> bool:
    """All terms in context+content, and at least one term in the block itself –
    otherwise a module whose *name* matches would repeat every one of its rules."""
    if not _matches(terms, *ctx, content):
        return False
    c = content.lower()
    return not terms or any(t in c for t in terms)


def search(profile: Profile, q: str = "", kind: str = "", category: str = "", scope: str = "selected") -> Result:
    terms = [t for t in q.lower().split() if t]
    selected = profile.selected
    rels = sorted(selected) if scope == "selected" else catalog.all_module_rels()
    if category:
        rels = [r for r in rels if r.split("/")[0] == category]
    if kind in ("include", "exclude"):
        rels = [r for r in rels if _kind(r) == kind]

    hits: list[Hit] = []
    total = 0
    modules_hit: set[str] = set()
    for rel in rels:
        try:
            mod = catalog.parsed_module(rel)
        except Exception:
            continue
        cat = rel.split("/")[0]
        base = dict(rel=rel, category=cat, kind=_kind(rel), source=overlay.source_of(rel), selected=rel in selected)
        module_hits: list[Hit] = []
        for rg in mod.rulegroups:
            for ev in rg.events:
                ctx = (rel, rg.name, ev.event_type, ev.onmatch)
                for r in ev.rules:
                    content = " ".join([r.name] + [f"{c.field} {c.condition} {c.value} {c.name}" for c in r.conditions])
                    if _content_hit(terms, ctx, content):
                        t = r.technique
                        module_hits.append(Hit(**base, group_name=rg.name, group_relation=rg.group_relation,
                                               event_type=ev.event_type, onmatch=ev.onmatch, block="rule",
                                               name=r.name, xml=sysmon_xml.rule_to_xml(r), techniques=[t] if t else []))
                for c in ev.conditions:
                    if _content_hit(terms, ctx, f"{c.field} {c.condition} {c.value} {c.name}"):
                        m = sysmon_xml.TECH_RE.search(c.name or "")
                        module_hits.append(Hit(**base, group_name=rg.name, group_relation=rg.group_relation,
                                               event_type=ev.event_type, onmatch=ev.onmatch, block="condition",
                                               name=c.name, xml=sysmon_xml.condition_to_xml(c),
                                               techniques=[(m.group(1), m.group(2))] if m else []))
        if not module_hits:
            # No block matched on its own content: does the module as a whole (path, group names,
            # events) match? Then show the module once, in full.
            module_hay = [rel] + [rg.name for rg in mod.rulegroups] + \
                         [f"{ev.event_type} onmatch={ev.onmatch}" for rg in mod.rulegroups for ev in rg.events]
            if _matches(terms, *module_hay):
                try:
                    xml = overlay.read_text(rel)
                except OSError:
                    xml = ""
                module_hits.append(Hit(**base, group_name="", group_relation="", event_type="", onmatch="",
                                       block="module", name="", xml=xml, techniques=mod.techniques[:8]))
        if module_hits:
            modules_hit.add(rel)
            total += len(module_hits)
            room = MAX_HITS - len(hits)
            if room > 0:
                hits.extend(module_hits[:room])
    return Result(hits=hits, total=total, modules_scanned=len(rels), modules_hit=len(modules_hit),
                  terms=terms, truncated=total > len(hits))
