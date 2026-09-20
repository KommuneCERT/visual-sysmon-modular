// ATT&CK coverage: matrix from the engine's coverage report + tagged-rule statistics (port of attack.py).
import { ruleTechnique } from "./model.js";

export const TACTIC_ORDER = [
  "reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation",
  "defense-evasion", "stealth", "defense-impairment", "credential-access", "discovery", "lateral-movement",
  "collection", "command-and-control", "exfiltration", "impact",
];
export const tacticLabel = t => t.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase()).replace("And", "and");
const level = n => (n <= 1 ? 1 : n <= 4 ? 2 : n <= 9 ? 3 : 4);

export function buildMatrix(report) {
  const techniques = report.techniques || [];
  const byId = Object.fromEntries(techniques.map(t => [t.id, t]));
  const perTactic = new Map();
  for (const t of techniques) {
    const parentId = t.id.split(".")[0];
    for (const tac of (t.tactics && t.tactics.length ? t.tactics : ["unmapped"])) {
      if (!perTactic.has(tac)) perTactic.set(tac, new Map());
      const col = perTactic.get(tac);
      if (!col.has(parentId)) col.set(parentId, { id: parentId, name: byId[parentId]?.name ?? "", count: 0, modules: [], direct: false, subs: [] });
      const p = col.get(parentId);
      if (t.id.includes(".")) p.subs.push({ id: t.id, name: t.name, count: t.count, modules: t.modules });
      else { p.direct = true; p.name = t.name; p.modules = t.modules; p.count += t.count; }
    }
  }
  const order = Object.fromEntries(TACTIC_ORDER.map((t, i) => [t, i]));
  const rank = t => (t === "unmapped" ? 999 : (order[t] ?? 900));
  const columns = [...perTactic.keys()].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b)).map(tac => {
    const nodes = [...perTactic.get(tac).values()].map(n => {
      n.subs.sort((a, b) => a.id.localeCompare(b.id));
      n.total = n.count + n.subs.reduce((s, x) => s + x.count, 0);
      n.module_count = new Set([...n.modules, ...n.subs.flatMap(s => s.modules)]).size;
      n.level = level(n.total);
      if (!n.name) n.name = n.subs.length ? n.subs[0].name.split(":")[0] : n.id;
      n.hay = [n.id, n.name, ...n.modules, ...n.subs.flatMap(s => [s.id, s.name, ...s.modules])].join(" ").toLowerCase();
      return n;
    }).sort((a, b) => a.id.localeCompare(b.id));
    return { tactic: tac, label: tacticLabel(tac), techniques: nodes, technique_count: nodes.length + nodes.reduce((s, n) => s + n.subs.length, 0), hits: report.tactics?.[tac] ?? nodes.reduce((s, n) => s + n.total, 0) };
  });
  return {
    columns, techniques: [...techniques].sort((a, b) => a.id.localeCompare(b.id)), byId,
    technique_total: techniques.length,
    parent_total: new Set(techniques.map(t => t.id.split(".")[0])).size,
    sub_total: techniques.filter(t => t.id.includes(".")).length,
    tactic_total: columns.filter(c => c.tactic !== "unmapped").length,
    include: report.include ?? 0, exclude: report.exclude ?? 0, events: report.events ?? [],
  };
}

export function ruleTagging(catalog, rels) {
  let tagged = 0, untagged = 0;
  const untaggedModules = {};
  for (const rel of rels) {
    let mod;
    try { mod = catalog.parsed(rel); } catch { continue; }
    for (const rg of mod.rulegroups) {
      const groupTag = !!ruleTechnique(rg.name);
      for (const ev of rg.events) {
        if (ev.onmatch !== "include") continue;
        for (const r of ev.rules) { if (ruleTechnique(r.name) || groupTag) tagged++; else { untagged++; untaggedModules[rel] = (untaggedModules[rel] || 0) + 1; } }
        for (const c of ev.conditions) { if (groupTag || ruleTechnique(c.name)) tagged++; else { untagged++; untaggedModules[rel] = (untaggedModules[rel] || 0) + 1; } }
      }
    }
  }
  const total = tagged + untagged;
  return { tagged, untagged, total, pct: total ? Math.round(100 * tagged / total) : 0,
    untagged_modules: Object.entries(untaggedModules).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])) };
}
