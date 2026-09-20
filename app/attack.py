"""ATT&CK coverage: turn the CLI's coverage JSON into a tactic × technique matrix
and count how many of the selected rules actually carry technique metadata."""
from __future__ import annotations

from collections import defaultdict

from . import overlay, sysmon_xml

# Enterprise kill-chain order; ATT&CK 19 added "stealth" and "defense-impairment".
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "stealth", "defense-impairment", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]


def tactic_label(t: str) -> str:
    return t.replace("-", " ").title().replace("And", "and")


def _level(count: int) -> int:
    return 1 if count <= 1 else 2 if count <= 4 else 3 if count <= 9 else 4


def build_matrix(coverage: dict) -> dict:
    """Group techniques per tactic, nesting sub-techniques under their parent."""
    techniques = coverage.get("techniques", [])
    by_id = {t["id"]: t for t in techniques}
    per_tactic: dict[str, dict[str, dict]] = defaultdict(dict)   # tactic -> parent id -> node

    for t in techniques:
        tactics = t.get("tactics") or ["unmapped"]
        parent_id = t["id"].split(".")[0]
        for tac in tactics:
            col = per_tactic[tac]
            parent = col.setdefault(parent_id, {
                "id": parent_id, "name": by_id.get(parent_id, {}).get("name", ""), "count": 0,
                "modules": [], "direct": False, "subs": [],
            })
            if "." in t["id"]:
                parent["subs"].append({"id": t["id"], "name": t["name"], "count": t["count"], "modules": t["modules"]})
            else:
                parent["direct"] = True
                parent["name"] = t["name"]
                parent["modules"] = t["modules"]
                parent["count"] += t["count"]

    order = {t: i for i, t in enumerate(TACTIC_ORDER)}
    columns = []
    for tac in sorted(per_tactic, key=lambda t: (order.get(t, 900 if t != "unmapped" else 999), t)):
        nodes = []
        for node in per_tactic[tac].values():
            node["subs"].sort(key=lambda s: s["id"])
            node["total"] = node["count"] + sum(s["count"] for s in node["subs"])
            mods = set(node["modules"])
            for s in node["subs"]:
                mods.update(s["modules"])
            node["module_count"] = len(mods)
            node["level"] = _level(node["total"])
            if not node["name"]:
                node["name"] = node["subs"][0]["name"].split(":")[0] if node["subs"] else node["id"]
            nodes.append(node)
        nodes.sort(key=lambda n: n["id"])
        columns.append({
            "tactic": tac, "label": tactic_label(tac), "techniques": nodes,
            "technique_count": len(nodes) + sum(len(n["subs"]) for n in nodes),
            "hits": coverage.get("tactics", {}).get(tac, sum(n["total"] for n in nodes)),
        })

    techniques_sorted = sorted(techniques, key=lambda t: t["id"])
    return {
        "columns": columns,
        "techniques": techniques_sorted,
        "technique_total": len(techniques),
        "parent_total": len({t["id"].split(".")[0] for t in techniques}),
        "sub_total": sum(1 for t in techniques if "." in t["id"]),
        "tactic_total": sum(1 for c in columns if c["tactic"] != "unmapped"),
        "include": coverage.get("include", 0),
        "exclude": coverage.get("exclude", 0),
        "events": coverage.get("events", []),
    }


def rule_tagging(module_rels: list[str]) -> dict:
    """Count include rules with vs. without ATT&CK metadata (RuleGroup tags inherit)."""
    tagged = untagged = 0
    untagged_modules: dict[str, int] = {}
    for rel in module_rels:
        try:
            mod = sysmon_xml.parse(overlay.read_text(rel))
        except Exception:
            continue
        for rg in mod.rulegroups:
            group_tag = sysmon_xml.TECH_RE.search(rg.name or "") is not None
            for ev in rg.events:
                if ev.onmatch != "include":
                    continue
                for r in ev.rules:
                    if r.technique or group_tag:
                        tagged += 1
                    else:
                        untagged += 1
                        untagged_modules[rel] = untagged_modules.get(rel, 0) + 1
                for c in ev.conditions:
                    if group_tag or sysmon_xml.TECH_RE.search(c.name or ""):
                        tagged += 1
                    else:
                        untagged += 1
                        untagged_modules[rel] = untagged_modules.get(rel, 0) + 1
    total = tagged + untagged
    return {
        "tagged": tagged, "untagged": untagged, "total": total,
        "pct": round(100 * tagged / total) if total else 0,
        "untagged_modules": sorted(untagged_modules.items(), key=lambda kv: (-kv[1], kv[0])),
    }
