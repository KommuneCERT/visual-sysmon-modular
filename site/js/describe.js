// Human-readable sentences for rules, so a module card or a search hit explains
// itself without reading XML. Pure functions over the model (model.js).

const OP = {
  "is": "is", "is not": "is not", "is any": "is one of",
  "contains": "contains", "contains any": "contains any of", "contains all": "contains all of",
  "excludes": "does not contain", "excludes any": "is missing one of", "excludes all": "does not contain any of",
  "begin with": "starts with", "end with": "ends with", "not begin with": "does not start with", "not end with": "does not end with",
  "image": "is the process", "not image": "is not the process",
  "less than": "sorts before", "more than": "sorts after",
};
const MULTI = new Set(["is any", "contains any", "contains all", "excludes any", "excludes all"]);
const code = v => "`" + String(v).replace(/`/g, "'") + "`";

export function describeCondition(c) {
  const op = (c.condition || "is").toLowerCase();
  const wording = OP[op] || op;
  const value = c.value ?? "";
  if (MULTI.has(op)) {
    const parts = value.split(";").map(s => s.trim()).filter(Boolean);
    return `${c.field} ${wording} ${parts.map(code).join(", ")}`;
  }
  return `${c.field} ${wording} ${code(value)}`;
}

const joinWith = (parts, rel) => parts.join(rel === "or" ? " or " : " and ");

export function describeRule(rule) {
  if (!rule.conditions.length) return "(no conditions – matches nothing)";
  return joinWith(rule.conditions.map(describeCondition), (rule.group_relation || "and").toLowerCase());
}

// Bare conditions follow Sysmon's classic combination unless the RuleGroup sets a relation.
export function describeBare(conditions, groupRelation) {
  if (!conditions.length) return "";
  const rel = (groupRelation || "").toLowerCase();
  if (rel === "and" || rel === "or") return joinWith(conditions.map(describeCondition), rel);
  const byField = new Map();
  for (const c of conditions) (byField.get(c.field) || byField.set(c.field, []).get(c.field)).push(describeCondition(c));
  return [...byField.values()].map(g => (g.length > 1 ? "(" + g.join(" or ") + ")" : g[0])).join(" and ");
}

const verb = onmatch => (onmatch === "exclude" ? "Ignore" : "Log");

// One sentence per Rule / bare-condition block of an event filter.
export function describeEvent(ev, groupRelation) {
  const out = [];
  const head = `${verb(ev.onmatch)} ${ev.event_type} when `;
  if (ev.conditions.length) out.push(head + describeBare(ev.conditions, groupRelation));
  for (const r of ev.rules) out.push(head + describeRule(r));
  if (!out.length) out.push(`${verb(ev.onmatch)} nothing for ${ev.event_type} (empty ${ev.onmatch} filter)`);
  return out;
}

export function describeModule(model, { max = 3 } = {}) {
  const all = [];
  for (const rg of model.rulegroups) for (const ev of rg.events) all.push(...describeEvent(ev, rg.group_relation));
  return { sentences: all.slice(0, max), more: Math.max(0, all.length - max), total: all.length, all };
}

// For a search hit (rule or bare condition block).
export function describeHit(hit) {
  if (hit.block === "module") return "";
  const head = `${verb(hit.onmatch)} ${hit.event_type} when `;
  return head + hit.sentence;
}
