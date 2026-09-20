// Structured model of a sysmon-modular module (port of the Python sysmon_xml.py).
//   Sysmon > EventFiltering > RuleGroup* > <Event onmatch>* > (Rule* | Condition*)
// Includes a small XML parser so the same code runs in the browser and in Node tests.

export const TECH_RE = /technique_id=([^,]+),technique_name=(.*)/;

// ── minimal XML parser → {name, attrs:{}, children:[], text, line} ───────────
const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
export function unescapeXml(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#\d+|\w+);/g, (m, e) => {
    if (e[0] === "#") return String.fromCodePoint(e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
    return e in ENTITIES ? ENTITIES[e] : m;
  });
}
export function escapeXml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function escapeAttr(s) { return escapeXml(s).replace(/"/g, "&quot;"); }

export class XmlError extends Error {
  constructor(msg, line) { super(`line ${line}: ${msg}`); this.line = line; }
}

export function parseXml(src) {
  let i = 0, line = 1;
  const root = { name: "#document", attrs: {}, children: [], text: "", line: 1 };
  const stack = [root];
  const advance = n => { for (let k = 0; k < n; k++) if (src.charCodeAt(i + k) === 10) line++; i += n; };
  while (i < src.length) {
    if (src[i] !== "<") {
      const end = src.indexOf("<", i);
      const text = src.slice(i, end === -1 ? src.length : end);
      const top = stack[stack.length - 1];
      if (top !== root) top.text += unescapeXml(text);
      else if (text.trim()) throw new XmlError("text outside of root element", line);
      advance(text.length);
      continue;
    }
    if (src.startsWith("<!--", i)) {
      const end = src.indexOf("-->", i);
      if (end === -1) throw new XmlError("unterminated comment", line);
      advance(end + 3 - i);
      continue;
    }
    if (src.startsWith("<?", i)) {
      const end = src.indexOf("?>", i);
      if (end === -1) throw new XmlError("unterminated processing instruction", line);
      advance(end + 2 - i);
      continue;
    }
    if (src.startsWith("<![CDATA[", i)) {
      const end = src.indexOf("]]>", i);
      if (end === -1) throw new XmlError("unterminated CDATA", line);
      const top = stack[stack.length - 1];
      if (top !== root) top.text += src.slice(i + 9, end);
      advance(end + 3 - i);
      continue;
    }
    if (src.startsWith("<!", i)) {
      const end = src.indexOf(">", i);
      if (end === -1) throw new XmlError("unterminated declaration", line);
      advance(end + 1 - i);
      continue;
    }
    if (src.startsWith("</", i)) {
      const end = src.indexOf(">", i);
      if (end === -1) throw new XmlError("unterminated end tag", line);
      const name = src.slice(i + 2, end).trim();
      const top = stack[stack.length - 1];
      if (top === root) throw new XmlError(`unexpected end tag </${name}>`, line);
      if (top.name !== name) throw new XmlError(`end tag </${name}> does not match <${top.name}>`, line);
      stack.pop();
      advance(end + 1 - i);
      continue;
    }
    // start tag
    const m = /^<([^\s\/>]+)((?:\s+[^\s=\/>]+(?:\s*=\s*(?:"[^"]*"|'[^']*'))?)*)\s*(\/?)>/.exec(src.slice(i));
    if (!m) throw new XmlError("malformed start tag", line);
    const el = { name: m[1], attrs: {}, children: [], text: "", line };
    const attrRe = /([^\s=\/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'))?/g;
    let a;
    while ((a = attrRe.exec(m[2]))) el.attrs[a[1]] = unescapeXml(a[2] ?? a[3] ?? "");
    const top = stack[stack.length - 1];
    if (top === root && root.children.length) throw new XmlError("multiple document roots", line);
    top.children.push(el);
    if (!m[3]) stack.push(el);
    advance(m[0].length);
  }
  if (stack.length > 1) throw new XmlError(`unclosed element <${stack[stack.length - 1].name}>`, line);
  if (!root.children.length) throw new XmlError("empty XML document", line);
  return root.children[0];
}

export function isWellFormed(xml) {
  try { parseXml(xml); return [true, ""]; } catch (e) { return [false, e.message]; }
}

// ── module model ─────────────────────────────────────────────────────────────
const condFrom = el => ({ field: el.name, condition: el.attrs.condition ?? "", value: el.text.trim(), name: el.attrs.name ?? "" });

export function parseModule(xml) {
  const root = parseXml(xml);
  if (root.name !== "Sysmon") throw new XmlError("root element must be <Sysmon>", root.line);
  const ef = root.children.find(c => c.name === "EventFiltering");
  const groups = (ef ? ef.children : root.children).filter(c => c.name === "RuleGroup");
  return {
    schemaversion: root.attrs.schemaversion ?? "4.90",
    rulegroups: groups.map(rg => ({
      name: rg.attrs.name ?? "",
      group_relation: rg.attrs.groupRelation ?? "or",
      events: rg.children.map(ev => ({
        event_type: ev.name,
        onmatch: ev.attrs.onmatch ?? "include",
        conditions: ev.children.filter(c => c.name !== "Rule").map(condFrom),
        rules: ev.children.filter(c => c.name === "Rule").map(r => ({
          name: r.attrs.name ?? "",
          group_relation: r.attrs.groupRelation ?? "and",
          conditions: r.children.map(condFrom),
        })),
      })),
    })),
  };
}

function condXml(c, ind) {
  const attrs = (c.condition ? ` condition="${escapeAttr(c.condition)}"` : "") + (c.name ? ` name="${escapeAttr(c.name)}"` : "");
  return `${ind}<${c.field}${attrs}>${escapeXml(c.value ?? "")}</${c.field}>`;
}
export function conditionToXml(c) { return condXml(c, ""); }
export function ruleToXml(r, ind = "") {
  const attrs = (r.name ? ` name="${escapeAttr(r.name)}"` : "") + ` groupRelation="${escapeAttr(r.group_relation || "and")}"`;
  if (!r.conditions.length) return `${ind}<Rule${attrs}/>`;
  return [`${ind}<Rule${attrs}>`, ...r.conditions.map(c => condXml(c, ind + "  ")), `${ind}</Rule>`].join("\n");
}

export function toXml(model) {
  const out = [`<Sysmon schemaversion="${escapeAttr(model.schemaversion || "4.90")}">`, "  <EventFiltering>"];
  for (const rg of model.rulegroups) {
    out.push(`    <RuleGroup name="${escapeAttr(rg.name ?? "")}" groupRelation="${escapeAttr(rg.group_relation || "or")}">`);
    for (const ev of rg.events) {
      const open = `      <${ev.event_type} onmatch="${escapeAttr(ev.onmatch || "include")}"`;
      if (!ev.conditions.length && !ev.rules.length) { out.push(open + "/>"); continue; }
      out.push(open + ">");
      for (const c of ev.conditions) out.push(condXml(c, "        "));
      for (const r of ev.rules) out.push(ruleToXml(r, "        "));
      out.push(`      </${ev.event_type}>`);
    }
    out.push("    </RuleGroup>");
  }
  out.push("  </EventFiltering>", "</Sysmon>", "");
  return out.join("\n");
}

export function emptyModule(eventType, onmatch, groupName, schemaversion = "4.90") {
  return { schemaversion, rulegroups: [{ name: groupName, group_relation: "or", events: [{ event_type: eventType, onmatch, conditions: [], rules: [] }] }] };
}

export function ruleTechnique(name) {
  const m = TECH_RE.exec(name || "");
  return m ? [m[1], m[2]] : null;
}

// Summary used by module cards / search / coverage.
export function summarize(model) {
  const seen = new Map();
  const eventTypes = [];
  let ruleCount = 0;
  for (const rg of model.rulegroups) {
    const gt = ruleTechnique(rg.name);
    if (gt && !seen.has(gt[0])) seen.set(gt[0], gt[1]);
    for (const ev of rg.events) {
      if (!eventTypes.includes(ev.event_type)) eventTypes.push(ev.event_type);
      ruleCount += ev.rules.length + ev.conditions.length;
      for (const r of ev.rules) { const t = ruleTechnique(r.name); if (t && !seen.has(t[0])) seen.set(t[0], t[1]); }
      for (const c of ev.conditions) { const t = ruleTechnique(c.name); if (t && !seen.has(t[0])) seen.set(t[0], t[1]); }
    }
  }
  return {
    title: model.rulegroups.find(rg => rg.name)?.name ?? "",
    event_types: eventTypes,
    techniques: [...seen.entries()].sort((a, b) => a[0].localeCompare(b[0])),
    rule_count: ruleCount,
  };
}
