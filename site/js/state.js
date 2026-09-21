// User state: profiles, overlay and build history. Lives only in this browser
// (localStorage; build XML in IndexedDB) and can be exported/imported as one JSON file.
export const STORAGE_KEY = "vsm.v1";
export const EXPORT_FORMAT = 1;
// Target Sysmon executable versions understood by upstream's ResolveBinarySchema (major[.minor]).
export const SYSMON_TARGETS = [
  { v: "15.20", schema: "4.91", label: "Sysmon 15.20 or newer" },
  { v: "15", schema: "4.90", label: "Sysmon 15.0 – 15.19" },
  { v: "14.1", schema: "4.83", label: "Sysmon 14.1 – 14.16" },
  { v: "14", schema: "4.82", label: "Sysmon 14.0" },
  { v: "13.1", schema: "4.60", label: "Sysmon 13.1 – 13.34" },
  { v: "13", schema: "4.50", label: "Sysmon 13.0" },
  { v: "12", schema: "4.40", label: "Sysmon 12" },
];
export const SYSMON_VERSIONS = SYSMON_TARGETS.map(t => t.v);
export const SCHEMA_FOR_VERSION = Object.fromEntries(SYSMON_TARGETS.map(t => [t.v, t.schema]));
export const DEFAULT_SYSMON_VERSION = "15.20";
export const MAX_BUILDS = 10;

const now = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export function slugify(name) {
  const s = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
  if (!SLUG_RE.test(s)) throw new Error("profile name must contain letters or digits");
  return s;
}

export function newProfile(slug, name, opts = {}) {
  return {
    // analyze / preserve_comments / force_grouprelation_or are kept for export compatibility but no longer user-editable:
    // the build always analyses, always preserves comments (upstream's release setting) and never forces "or".
    slug, name, description: "", sysmon_version: DEFAULT_SYSMON_VERSION, unsupported: "exclude", preserve_comments: true,
    force_grouprelation_or: false, analyze: true, modules: [], created: now(), updated: now(), ...opts,
  };
}

export function emptyState() { return { profiles: {}, current: "", overlay: {}, builds: {}, onboarded: false }; }

export function presetProfile(slug, name, preset, extra = {}) {
  return newProfile(slug, name, { modules: [...preset.modules], preset: preset.id, description: preset.tagline || "", ...(preset.options || {}), ...extra });
}

export function loadState(storage = globalThis.localStorage) {
  try {
    const raw = storage?.getItem(STORAGE_KEY);
    if (raw) { const s = JSON.parse(raw); return { ...emptyState(), ...s }; }
  } catch { /* private mode, quota, corrupt json */ }
  return emptyState();
}

export function saveState(state, storage = globalThis.localStorage) {
  try { storage?.setItem(STORAGE_KEY, JSON.stringify(state)); return true; } catch { return false; }
}

// Keep only modules that still exist; sorted & unique.
export function normalizeProfile(profile, catalog) {
  profile.modules = [...new Set(profile.modules)].filter(r => catalog.exists(r)).sort();
  profile.updated = now();
  return profile;
}

export function ensureDefault(state, catalog) {
  if (Object.keys(state.profiles).length) {
    if (!state.profiles[state.current]) state.current = Object.keys(state.profiles)[0];
    return state;
  }
  const balanced = (catalog.presets || []).find(p => p.id === "balanced");
  const p = balanced ? presetProfile("default", "default", balanced, { description: "Upstream's default sysmonconfig.xml (Balanced preset)" })
    : newProfile("default", "default", { description: "All upstream modules", modules: catalog.allRels() });
  state.profiles.default = p;
  state.current = "default";
  return state;
}

// ── export / import ──────────────────────────────────────────────────────────
export function exportState(state, upstream) {
  return {
    format: EXPORT_FORMAT, app: "visual-sysmon-modular", exported: now(),
    upstream: upstream ? { commit: upstream.commit, date: upstream.date } : null,
    profiles: state.profiles, current: state.current, overlay: state.overlay,
  };
}

export function importState(state, data, mode = "replace") {
  if (!data || data.format !== EXPORT_FORMAT || typeof data.profiles !== "object") throw new Error("not a Visual Sysmon Modular export file");
  const profiles = {}, overlay = {};
  for (const [slug, p] of Object.entries(data.profiles)) if (SLUG_RE.test(slug) && p && Array.isArray(p.modules)) profiles[slug] = { ...newProfile(slug, p.name || slug), ...p, slug };
  for (const [rel, xml] of Object.entries(data.overlay || {})) if (typeof xml === "string" && /^\d[\w]*\/[\w.-]+\.xml$/.test(rel)) overlay[rel] = xml;
  if (mode === "replace") {
    state.profiles = profiles; state.overlay = overlay; state.builds = {};
    state.current = profiles[data.current] ? data.current : Object.keys(profiles)[0] || "";
  } else {
    Object.assign(state.profiles, profiles); Object.assign(state.overlay, overlay);
    if (!state.profiles[state.current]) state.current = Object.keys(state.profiles)[0] || "";
  }
  return { profiles: Object.keys(profiles).length, overlay: Object.keys(overlay).length };
}

// ── build history (meta in state, XML in IndexedDB) ──────────────────────────
export function addBuild(state, slug, meta) {
  const list = state.builds[slug] || (state.builds[slug] = []);
  list.unshift(meta);
  const dropped = list.splice(MAX_BUILDS);
  return dropped.map(b => b.id);
}

const DB = "vsm-builds", STORE = "xml";
function openDb() {
  return new Promise((resolve, reject) => {
    if (!globalThis.indexedDB) return resolve(null);
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
const memXml = new Map(); // fallback when IndexedDB is unavailable
export async function putBuildXml(id, xml) {
  memXml.set(id, xml);
  try { const db = await openDb(); if (!db) return; await new Promise((res, rej) => { const tx = db.transaction(STORE, "readwrite"); tx.objectStore(STORE).put(xml, id); tx.oncomplete = res; tx.onerror = () => rej(tx.error); }); } catch { /* ignore */ }
}
export async function getBuildXml(id) {
  if (memXml.has(id)) return memXml.get(id);
  try { const db = await openDb(); if (!db) return null; return await new Promise((res, rej) => { const r = db.transaction(STORE).objectStore(STORE).get(id); r.onsuccess = () => res(r.result ?? null); r.onerror = () => rej(r.error); }); } catch { return null; }
}
export async function deleteBuildXml(ids) {
  for (const id of ids) memXml.delete(id);
  try { const db = await openDb(); if (!db) return; await new Promise((res, rej) => { const tx = db.transaction(STORE, "readwrite"); for (const id of ids) tx.objectStore(STORE).delete(id); tx.oncomplete = res; tx.onerror = () => rej(tx.error); }); } catch { /* ignore */ }
}
