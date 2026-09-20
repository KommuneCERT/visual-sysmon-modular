// Effective module catalog = upstream catalog.json + the user's overlay (edited/custom modules).
import { parseModule, summarize } from "./model.js";

export const CATEGORY_RE = /^\d+(?:_\d+)*_[a-z0-9_]+$/;
const CAT_PREFIX_RE = /^(\d+(?:_\d+)*)_(.+)$/;

export function categoryMeta(dirname) {
  const m = CAT_PREFIX_RE.exec(dirname);
  return { dirname, event_ids: m ? m[1].split("_") : [], label: m ? m[2].replace(/_/g, " ").replace(/^./, c => c.toUpperCase()) : dirname };
}
const sortKey = d => { const m = CAT_PREFIX_RE.exec(d); return m ? parseInt(m[1].split("_")[0], 10) : 999; };

export function kindOf(rel) {
  const f = rel.split("/")[1] ?? "";
  return f.startsWith("include_") ? "include" : f.startsWith("exclude_") ? "exclude" : "other";
}
export function filenameTitle(fname) {
  const stem = fname.replace(/\.xml$/, "").replace(/^(include|exclude)_/, "");
  return stem.replace(/[_-]+/g, " ").trim().replace(/^./, c => c.toUpperCase()) || fname;
}
export function validRel(rel) {
  const parts = (rel || "").split("/");
  return parts.length === 2 && CATEGORY_RE.test(parts[0]) && parts[1].endsWith(".xml") && !rel.includes("..");
}
export function slugify(name) {
  const s = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  if (!s) throw new Error("name is empty");
  return s;
}

const summaryCache = new Map(); // xml → summary (modules are immutable strings)
function summaryFor(xml) {
  let s = summaryCache.get(xml);
  if (!s) {
    try { s = { ...summarize(parseModule(xml)), error: "" }; }
    catch (e) { s = { title: "", event_types: [], techniques: [], rule_count: 0, error: e.message }; }
    if (summaryCache.size > 2000) summaryCache.clear();
    summaryCache.set(xml, s);
  }
  return s;
}

export class Catalog {
  constructor(data, overlay) {
    this.upstream = new Map(data.modules.map(m => [m.rel, m.xml]));
    this.template = data.template || "";
    this.examples = data.examples || {};
    this.presets = data.presets || [];
    this.mdeCovered = data.mde_covered || [];
    this.generated = data.generated;
    this.upstreamCategories = data.categories.map(c => c.dirname);
    this.overlay = overlay; // live object {rel: xml}
  }
  exists(rel) { return this.overlay[rel] !== undefined || this.upstream.has(rel); }
  xml(rel) { return this.overlay[rel] ?? this.upstream.get(rel); }
  sourceOf(rel) { return this.overlay[rel] !== undefined ? (this.upstream.has(rel) ? "edited" : "custom") : "upstream"; }
  categoryDirs() {
    const set = new Set(this.upstreamCategories);
    for (const rel of Object.keys(this.overlay)) set.add(rel.split("/")[0]);
    return [...set].filter(d => CATEGORY_RE.test(d)).sort((a, b) => sortKey(a) - sortKey(b) || a.localeCompare(b));
  }
  moduleRels(category) {
    const files = new Set();
    for (const rel of this.upstream.keys()) if (rel.startsWith(category + "/")) files.add(rel);
    for (const rel of Object.keys(this.overlay)) if (rel.startsWith(category + "/")) files.add(rel);
    return [...files].sort();
  }
  allRels() { return this.categoryDirs().flatMap(d => this.moduleRels(d)); }
  module(rel) {
    const xml = this.xml(rel);
    if (xml === undefined) return null;
    const [category, filename] = rel.split("/");
    const s = summaryFor(xml);
    return { rel, category, filename, kind: kindOf(rel), source: this.sourceOf(rel), ...s, title: s.title || filenameTitle(filename) };
  }
  parsed(rel) { return parseModule(this.xml(rel)); }
  categories() {
    return this.categoryDirs().map(d => ({ ...categoryMeta(d), modules: this.moduleRels(d).map(r => this.module(r)) })).filter(c => c.modules.length);
  }
  overlayRels() { return Object.keys(this.overlay).filter(validRel).sort(); }
}
