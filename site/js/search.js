// Free-text search over a profile's modules → matching <Rule>/condition blocks with context (port of search.py).
import { ruleToXml, conditionToXml, ruleTechnique } from "./model.js";
import { kindOf } from "./catalog.js";

export const MAX_HITS = 150;

const matches = (terms, ...parts) => { const hay = parts.filter(Boolean).join(" ").toLowerCase(); return terms.every(t => hay.includes(t)); };
function contentHit(terms, ctx, content) {
  if (!matches(terms, ...ctx, content)) return false;
  const c = content.toLowerCase();
  return !terms.length || terms.some(t => c.includes(t));
}

export function search(catalog, profile, { q = "", kind = "", category = "", scope = "selected" } = {}) {
  const terms = q.toLowerCase().split(/\s+/).filter(Boolean);
  const selected = new Set(profile.modules);
  let rels = scope === "selected" ? [...selected].sort() : catalog.allRels();
  if (category) rels = rels.filter(r => r.split("/")[0] === category);
  if (kind === "include" || kind === "exclude") rels = rels.filter(r => kindOf(r) === kind);

  const hits = [];
  let total = 0;
  const modulesHit = new Set();
  for (const rel of rels) {
    let mod;
    try { mod = catalog.parsed(rel); } catch { continue; }
    const base = { rel, category: rel.split("/")[0], kind: kindOf(rel), source: catalog.sourceOf(rel), selected: selected.has(rel) };
    const moduleHits = [];
    for (const rg of mod.rulegroups) {
      for (const ev of rg.events) {
        const ctx = [rel, rg.name, ev.event_type, ev.onmatch];
        const common = { group_name: rg.name, group_relation: rg.group_relation, event_type: ev.event_type, onmatch: ev.onmatch };
        for (const r of ev.rules) {
          const content = [r.name, ...r.conditions.map(c => `${c.field} ${c.condition} ${c.value} ${c.name}`)].join(" ");
          if (contentHit(terms, ctx, content)) {
            const t = ruleTechnique(r.name);
            moduleHits.push({ ...base, ...common, block: "rule", name: r.name, xml: ruleToXml(r), techniques: t ? [t] : [] });
          }
        }
        for (const c of ev.conditions) {
          if (contentHit(terms, ctx, `${c.field} ${c.condition} ${c.value} ${c.name}`)) {
            const t = ruleTechnique(c.name);
            moduleHits.push({ ...base, ...common, block: "condition", name: c.name, xml: conditionToXml(c), techniques: t ? [t] : [] });
          }
        }
      }
    }
    if (!moduleHits.length) {
      const hay = [rel, ...mod.rulegroups.map(rg => rg.name), ...mod.rulegroups.flatMap(rg => rg.events.map(ev => `${ev.event_type} onmatch=${ev.onmatch}`))];
      if (matches(terms, ...hay)) {
        const info = catalog.module(rel);
        moduleHits.push({ ...base, group_name: "", group_relation: "", event_type: "", onmatch: "", block: "module", name: "", xml: catalog.xml(rel), techniques: info.techniques.slice(0, 8) });
      }
    }
    if (moduleHits.length) {
      modulesHit.add(rel);
      total += moduleHits.length;
      const room = MAX_HITS - hits.length;
      if (room > 0) hits.push(...moduleHits.slice(0, room));
    }
  }
  return { hits, total, modules_scanned: rels.length, modules_hit: modulesHit.size, terms, truncated: total > hits.length };
}
