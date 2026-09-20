"""Structured model of a single sysmon-modular module.

A module is:  Sysmon > EventFiltering > RuleGroup* > <Event onmatch>* > (Rule* | Condition*)

The model is deliberately plain (dataclasses <-> dict) so the browser editor
can round-trip it as JSON. Parsing uses lxml; serialising produces the same
2-space layout upstream uses.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from lxml import etree

SCHEMA_PATH = Path(__file__).parent / "schema" / "fields.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text())
EVENT_TYPES: list[str] = list(SCHEMA["events"].keys())
CONDITIONS: list[str] = SCHEMA["conditions"]

TECH_RE = re.compile(r"technique_id=([^,]+),technique_name=(.*)")


@dataclass
class Condition:
    field: str
    condition: str = "is"
    value: str = ""
    name: str = ""

    def to_xml(self) -> etree._Element:
        el = etree.Element(self.field)
        if self.condition:
            el.set("condition", self.condition)
        if self.name:
            el.set("name", self.name)
        el.text = self.value
        return el


@dataclass
class Rule:
    name: str = ""
    group_relation: str = "and"
    conditions: list[Condition] = field(default_factory=list)

    @property
    def technique(self) -> tuple[str, str] | None:
        m = TECH_RE.search(self.name or "")
        return (m.group(1), m.group(2)) if m else None


@dataclass
class EventFilter:
    event_type: str
    onmatch: str = "include"
    conditions: list[Condition] = field(default_factory=list)  # bare conditions
    rules: list[Rule] = field(default_factory=list)


@dataclass
class RuleGroup:
    name: str = ""
    group_relation: str = "or"
    events: list[EventFilter] = field(default_factory=list)


@dataclass
class Module:
    schemaversion: str = "4.90"
    rulegroups: list[RuleGroup] = field(default_factory=list)

    # ── conversions ──────────────────────────────────────────────
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Module":
        return cls(
            schemaversion=d.get("schemaversion") or "4.90",
            rulegroups=[
                RuleGroup(
                    name=rg.get("name", ""),
                    group_relation=rg.get("group_relation", "or"),
                    events=[
                        EventFilter(
                            event_type=ev["event_type"],
                            onmatch=ev.get("onmatch", "include"),
                            conditions=[Condition(**c) for c in ev.get("conditions", [])],
                            rules=[
                                Rule(
                                    name=r.get("name", ""),
                                    group_relation=r.get("group_relation", "and"),
                                    conditions=[Condition(**c) for c in r.get("conditions", [])],
                                )
                                for r in ev.get("rules", [])
                            ],
                        )
                        for ev in rg.get("events", [])
                    ],
                )
                for rg in d.get("rulegroups", [])
            ],
        )

    # ── summary helpers used by the catalog ──────────────────────
    @property
    def techniques(self) -> list[tuple[str, str]]:
        seen: dict[str, str] = {}
        for rg in self.rulegroups:
            m = TECH_RE.search(rg.name or "")
            if m:
                seen.setdefault(m.group(1), m.group(2))
            for ev in rg.events:
                for r in ev.rules:
                    t = r.technique
                    if t:
                        seen.setdefault(t[0], t[1])
        return sorted(seen.items())

    @property
    def event_types(self) -> list[str]:
        out: list[str] = []
        for rg in self.rulegroups:
            for ev in rg.events:
                if ev.event_type not in out:
                    out.append(ev.event_type)
        return out

    @property
    def onmatch_kinds(self) -> set[str]:
        return {ev.onmatch for rg in self.rulegroups for ev in rg.events}

    @property
    def rule_count(self) -> int:
        return sum(len(ev.rules) + len(ev.conditions) for rg in self.rulegroups for ev in rg.events)


# ── parsing ──────────────────────────────────────────────────────────────────
def _cond_from_el(el: etree._Element) -> Condition:
    return Condition(
        field=el.tag,
        condition=el.get("condition", ""),
        value=(el.text or "").strip(),
        name=el.get("name", ""),
    )


def parse(text: str | bytes) -> Module:
    if isinstance(text, str):
        text = text.encode()
    parser = etree.XMLParser(remove_comments=True, remove_blank_text=True)
    root = etree.fromstring(text, parser)
    if root.tag != "Sysmon":
        raise ValueError("root element must be <Sysmon>")
    mod = Module(schemaversion=root.get("schemaversion", "4.90"))
    ef = root.find("EventFiltering")
    groups = ef.findall("RuleGroup") if ef is not None else root.findall("RuleGroup")
    for rg_el in groups:
        rg = RuleGroup(name=rg_el.get("name", ""), group_relation=rg_el.get("groupRelation", "or"))
        for ev_el in rg_el:
            if not isinstance(ev_el.tag, str):
                continue
            ev = EventFilter(event_type=ev_el.tag, onmatch=ev_el.get("onmatch", "include"))
            for child in ev_el:
                if not isinstance(child.tag, str):
                    continue
                if child.tag == "Rule":
                    rule = Rule(name=child.get("name", ""), group_relation=child.get("groupRelation", "and"))
                    rule.conditions = [_cond_from_el(c) for c in child if isinstance(c.tag, str)]
                    ev.rules.append(rule)
                else:
                    ev.conditions.append(_cond_from_el(child))
            rg.events.append(ev)
        mod.rulegroups.append(rg)
    return mod


def parse_file(path: Path) -> Module:
    return parse(path.read_bytes())


# ── serialising ──────────────────────────────────────────────────────────────
def to_xml(mod: Module) -> str:
    root = etree.Element("Sysmon", schemaversion=mod.schemaversion)
    ef = etree.SubElement(root, "EventFiltering")
    for rg in mod.rulegroups:
        rg_el = etree.SubElement(ef, "RuleGroup")
        rg_el.set("name", rg.name or "")
        rg_el.set("groupRelation", rg.group_relation or "or")
        for ev in rg.events:
            ev_el = etree.SubElement(rg_el, ev.event_type, onmatch=ev.onmatch or "include")
            for c in ev.conditions:
                ev_el.append(c.to_xml())
            for r in ev.rules:
                r_el = etree.SubElement(ev_el, "Rule")
                if r.name:
                    r_el.set("name", r.name)
                r_el.set("groupRelation", r.group_relation or "and")
                for c in r.conditions:
                    r_el.append(c.to_xml())
    etree.indent(root, space="  ")
    return etree.tostring(root, encoding="unicode") + "\n"


def _el_xml(el: etree._Element) -> str:
    etree.indent(el, space="  ")
    return etree.tostring(el, encoding="unicode")


def rule_to_xml(rule: Rule) -> str:
    r_el = etree.Element("Rule")
    if rule.name:
        r_el.set("name", rule.name)
    r_el.set("groupRelation", rule.group_relation or "and")
    for c in rule.conditions:
        r_el.append(c.to_xml())
    return _el_xml(r_el)


def condition_to_xml(cond: Condition) -> str:
    return _el_xml(cond.to_xml())


def empty_module(event_type: str, onmatch: str, group_name: str, schemaversion: str = "4.90") -> Module:
    return Module(
        schemaversion=schemaversion,
        rulegroups=[RuleGroup(name=group_name, group_relation="or", events=[EventFilter(event_type=event_type, onmatch=onmatch)])],
    )


def is_well_formed(text: str) -> tuple[bool, str]:
    try:
        etree.fromstring(text.encode())
        return True, ""
    except etree.XMLSyntaxError as exc:
        return False, str(exc)
