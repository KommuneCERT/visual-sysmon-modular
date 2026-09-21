// Free-text search over a profile's modules → matching <Rule>/condition blocks with context (port of search.py).
//
// Query syntax (all case-insensitive, terms are AND-ed):
//   word            substring of module path, group name, event, rule name, fields, operators, values
//   "some phrase"   phrase with spaces
//   -word           must NOT appear
//   /regex/         JavaScript regular expression (also -/regex/)
//   kind:include|exclude      module type              cat:22 | cat:dns_query   category (id or name part)
//   event:ProcessCreate       Sysmon event element     onmatch:include|exclude
//   field:CommandLine         a condition on this field   op:"contains any"     condition operator
//   tech:T1059 | tech:T1059.001  ATT&CK id (prefix)    value:powershell        substring of a value only
import { ruleToXml, conditionToXml, ruleTechnique } from "./model.js";
import { kindOf } from "./catalog.js";
import { describeRule, describeCondition } from "./describe.js";

export const MAX_HITS = 150;
const FILTER_KEYS = ["kind", "cat", "event", "onmatch", "field", "op", "tech", "value"];

export function parseQuery(q) {
  const terms = [], filters = {};
  const re = /(-)?(?:(\w+):)?(?:"([^"]*)"|\/((?:[^\/\\]|\\.)+)\/|(\S+))/g;
  let m;
  for (const mm of (q || "").matchAll(re)) {
    m = mm;
    const neg = !!m[1], key = (m[2] || "").toLowerCase(), phrase = m[3], regex = m[4], word = m[5];
    if (key && FILTER_KEYS.includes(key) && !neg) { filters[key] = (phrase ?? word ?? regex ?? "").toLowerCase(); continue; }
    const raw = key && !FILTER_KEYS.includes(key) ? `${key}:${phrase ?? word ?? ""}` : (phrase ?? word ?? "");
    if (regex !== undefined) { try { terms.push({ neg, re: new RegExp(regex, "i") }); } catch { terms.push({ neg, text: regex.toLowerCase() }); } }
    else if (raw) terms.push({ neg, text: raw.toLowerCase() });
  }
  return { terms, filters, hasBlockFilter: ["event", "onmatch", "field", "op", "tech", "value"].some(k => k in filters) };
}

const hit = (t, hay) => (t.re ? t.re.test(hay) : hay.includes(t.text));
const positives = terms => terms.filter(t => !t.neg);
// every positive term somewhere in ctx+content, no negative term anywhere, and at least one positive term in the content itself
function contentHit(terms, ctxHay, content) {
  const all = ctxHay + " " + content;
  for (const t of terms) { const h = hit(t, all); if (t.neg ? h : !h) return false; }
  const pos = positives(terms);
  return !pos.length || pos.some(t => hit(t, content));
}
function moduleHit(terms, hay) { return terms.every(t => (t.neg ? !hit(t, hay) : hit(t, hay))); }

function catMatches(cat, want) {
  const [ids, ...rest] = cat.split("_");
  return cat.includes(want) || ids.split("_").includes(want) || cat.replace(/^\d+(?:_\d+)*_/, "").includes(want) || cat.startsWith(want + "_") || cat.startsWith(want);
}
function condFilters(f, conds) {
  if (f.field && !conds.some(c => c.field.toLowerCase() === f.field)) return false;
  if (f.op && !conds.some(c => (c.condition || "is").toLowerCase() === f.op)) return false;
  if (f.value && !conds.some(c => (c.value || "").toLowerCase().includes(f.value))) return false;
  return true;
}
const techMatches = (f, tech) => !f.tech || (tech && tech[0].toLowerCase().startsWith(f.tech));

export function search(catalog, profile, { q = "", kind = "", category = "", scope = "selected" } = {}) {
  const { terms, filters: f, hasBlockFilter } = parseQuery(q);
  if (kind) f.kind = kind;
  const selected = new Set(profile.modules);
  let rels = scope === "selected" ? [...selected].sort() : catalog.allRels();
  if (category) rels = rels.filter(r => r.split("/")[0] === category);
  if (f.cat) rels = rels.filter(r => catMatches(r.split("/")[0], f.cat));
  if (f.kind === "include" || f.kind === "exclude") rels = rels.filter(r => kindOf(r) === f.kind);

  const hits = [];
  let total = 0;
  const modulesHit = [];
  for (const rel of rels) {
    let mod;
    try { mod = catalog.parsed(rel); } catch { continue; }
    const base = { rel, category: rel.split("/")[0], kind: kindOf(rel), source: catalog.sourceOf(rel), selected: selected.has(rel) };
    const moduleHits = [];
    for (const rg of mod.rulegroups) {
      const groupTech = ruleTechnique(rg.name);
      for (const ev of rg.events) {
        if (f.event && ev.event_type.toLowerCase() !== f.event) continue;
        if (f.onmatch && ev.onmatch !== f.onmatch) continue;
        const ctxHay = [rel, rg.name, ev.event_type, ev.onmatch].join(" ").toLowerCase();
        const common = { group_name: rg.name, group_relation: rg.group_relation, event_type: ev.event_type, onmatch: ev.onmatch };
        for (const r of ev.rules) {
          const t = ruleTechnique(r.name) || groupTech;
          if (!condFilters(f, r.conditions) || !techMatches(f, t)) continue;
          const content = [r.name, ...r.conditions.map(c => `${c.field} ${c.condition} ${c.value} ${c.name}`)].join(" ").toLowerCase();
          if (contentHit(terms, ctxHay, content) || (!positives(terms).length && moduleHit(terms, ctxHay + " " + content)))
            moduleHits.push({ ...base, ...common, block: "rule", name: r.name, xml: ruleToXml(r), techniques: t ? [t] : [], sentence: describeRule(r) });
        }
        for (const c of ev.conditions) {
          const t = ruleTechnique(c.name) || groupTech;
          if (!condFilters(f, [c]) || !techMatches(f, t)) continue;
          const content = `${c.field} ${c.condition} ${c.value} ${c.name}`.toLowerCase();
          if (contentHit(terms, ctxHay, content) || (!positives(terms).length && moduleHit(terms, ctxHay + " " + content)))
            moduleHits.push({ ...base, ...common, block: "condition", name: c.name, xml: conditionToXml(c), techniques: t ? [t] : [], sentence: describeCondition(c) });
        }
      }
    }
    if (!moduleHits.length && !hasBlockFilter && positives(terms).length) {
      const hay = [rel, ...mod.rulegroups.map(rg => rg.name), ...mod.rulegroups.flatMap(rg => rg.events.map(ev => `${ev.event_type} onmatch=${ev.onmatch}`))].join(" ").toLowerCase();
      if (moduleHit(terms, hay)) {
        const info = catalog.module(rel);
        moduleHits.push({ ...base, group_name: "", group_relation: "", event_type: "", onmatch: "", block: "module", name: "", xml: catalog.xml(rel), techniques: info.techniques.slice(0, 8), sentence: "" });
      }
    }
    if (moduleHits.length) {
      modulesHit.push(rel);
      total += moduleHits.length;
      const room = MAX_HITS - hits.length;
      if (room > 0) hits.push(...moduleHits.slice(0, room));
    }
  }
  return { hits, total, modules_scanned: rels.length, modules_hit: modulesHit.length, module_rels: modulesHit,
    terms: positives(terms).filter(t => t.text).map(t => t.text), truncated: total > hits.length, filters: f };
}
