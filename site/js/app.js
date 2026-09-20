// Visual Sysmon Modular – static SPA. Alpine store + page components.
import { Catalog, slugify as moduleSlug, validRel, kindOf } from "./catalog.js";
import { parseModule, toXml, emptyModule, isWellFormed, escapeXml } from "./model.js";
import * as S from "./state.js";
import { engine, engineStatus, onEngineStatus } from "./engine.js";
import { search } from "./search.js";
import { buildMatrix, ruleTagging } from "./attack.js";
import { parseList, formatList } from "./includelist.js";

export const APP_TITLE = "Visual Sysmon Modular";
const SEVERITY_ORDER = ["error", "warning", "performance", "recommendation", "info"];
const SEV_LABEL = { error: "Errors", warning: "Warnings", performance: "Performance", recommendation: "Recommendations", info: "Info" };

// Non-reactive globals (large / immutable). The reactive store only holds user state.
export const vsm = { catalog: null, fields: null, upstream: null, examples: {} };

// ── boot: fetch data before Alpine starts ────────────────────────────────────
async function boot() {
  const [catalogData, fields, upstream] = await Promise.all(
    ["data/catalog.json", "data/fields.json", "data/upstream.json"].map(u => fetch(u).then(r => { if (!r.ok) throw new Error(`${u}: ${r.status}`); return r.json(); })));
  const state = S.loadState();
  vsm.catalog = new Catalog(catalogData, state.overlay);
  vsm.fields = fields;
  vsm.upstream = upstream;
  S.ensureDefault(state, vsm.catalog);
  for (const p of Object.values(state.profiles)) S.normalizeProfile(p, vsm.catalog);
  S.saveState(state);
  return state;
}

// Alpine 3 auto-starts when its script runs, so it is injected only after the data is loaded.
boot().then(state => {
  window.__vsmInitialState = state;
  const s = document.createElement("script");
  s.src = "js/vendor/alpine.min.js";
  document.head.appendChild(s);
}).catch(err => {
  const el = document.getElementById("boot-error");
  el.textContent = `Failed to load site data: ${err.message}`;
  el.hidden = false;
});

// ── helpers ──────────────────────────────────────────────────────────────────
const nowStamp = () => new Date().toISOString().slice(0, 19).replace(/:/g, "-");
export function summarize(findings) {
  const out = Object.fromEntries(SEVERITY_ORDER.map(s => [s, 0]));
  for (const f of findings) out[f.severity] = (out[f.severity] || 0) + 1;
  return out;
}
export function download(name, text, type = "application/octet-stream") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function renderFindings(findings, { compact = true, summary = null, exitLabel = "" } = {}) {
  const cls = { error: "kc-callout--danger", warning: "kc-callout--warning", performance: "kc-callout--warning" };
  const icon = { error: "✖", warning: "⚠", performance: "⏱" };
  let html = '<div class="vsm-findings">';
  if (summary) html += `<div class="d-flex gap-2 flex-wrap mb-2"><span class="kc-severity kc-severity-high">${summary.error} errors</span><span class="kc-severity kc-severity-medium">${summary.warning} warnings</span><span class="kc-severity kc-severity-low">${summary.performance} performance</span><span class="kc-severity kc-severity-info">${summary.recommendation} recommendations</span>${exitLabel ? `<span class="kc-tag">${esc(exitLabel)}</span>` : ""}</div>`;
  if (!findings.length) html += '<div class="kc-callout kc-callout--success"><span class="kc-callout-icon">✓</span><div><p class="kc-callout-body mb-0">No findings – the XML is valid.</p></div></div>';
  for (const f of findings) {
    const loc = f.line ? ` <span class="text-muted small">· line ${f.line}</span>` : "";
    const sec = f.path && f.path !== "merged" && f.path !== "module.xml" ? ` <span class="text-muted small">· ${esc(f.path)}</span>` : "";
    html += `<div class="kc-callout ${cls[f.severity] || ""} ${compact ? "kc-callout--compact" : ""}"><span class="kc-callout-icon">${icon[f.severity] || "💡"}</span><div class="min-w-0"><div class="kc-callout-title"><code>${esc(f.code)}</code> ${esc(f.message)}${loc}${sec}</div>${f.detail ? `<div class="kc-callout-body vsm-detail">${esc(f.detail)}</div>` : ""}</div></div>`;
  }
  return html + "</div>";
}

export function renderDiff(diff, beforeId, afterId) {
  if (!diff || !diff.changes || !diff.changes.length) return `<div class="kc-callout kc-callout--success"><span class="kc-callout-icon">✓</span><div><p class="kc-callout-body mb-0">No semantic changes compared to build ${esc(beforeId)}.</p></div></div>`;
  let html = '<div class="d-flex gap-2 flex-wrap mb-2">';
  for (const [k, v] of Object.entries(diff.summary || {})) html += `<span class="kc-tag ${k.includes("added") ? "kc-tag-green" : k.includes("removed") ? "kc-tag-red" : ""}">${esc(k)}: ${v}</span>`;
  html += `<span class="text-muted small ms-auto">before: ${esc(beforeId)} → after: ${esc(afterId)}</span></div><div class="table-responsive"><table class="table table-sm kc-table"><thead><tr><th>Change</th><th>Impact</th><th>Event / technique</th><th>Detail</th></tr></thead><tbody>`;
  for (const c of diff.changes) {
    const what = c.rule ? `${esc(c.rule.name)} <span class="kc-tag">${esc(c.rule.onmatch)}</span>${(c.rule.techniques || []).map(t => ` <span class="kc-tag kc-tag-blue">${esc(t)}</span>`).join("")}` : c.technique ? `<span class="kc-tag kc-tag-blue">${esc(c.technique)}</span>` : "";
    html += `<tr><td><span class="kc-severity ${c.kind.includes("added") ? "kc-severity-low" : "kc-severity-high"}">${esc(c.kind)}</span></td><td class="small">${esc(c.impact)}</td><td class="small">${what}</td><td class="small font-monospace vsm-wrap">${esc(c.detail)}</td></tr>`;
  }
  return html + "</tbody></table></div>";
}

// ── Alpine registration ──────────────────────────────────────────────────────
document.addEventListener("alpine:init", () => {
  const A = window.Alpine;

  // <button class="vsm-help" x-help="'text'">?</button>
  A.directive("help", (el, { expression }, { evaluate }) => {
    el.classList.add("vsm-help");
    el.setAttribute("type", "button");
    el.setAttribute("aria-label", "Help");
    if (!el.textContent.trim()) el.textContent = "?";
    new window.bootstrap.Popover(el, { content: evaluate(expression), html: true, trigger: "hover focus", placement: "top" });
  });
  // <div x-include="'tpl-id'"> clones a <template id> into the element (shared markup)
  A.directive("include", (el, { expression }, { evaluate }) => {
    const tpl = document.getElementById(evaluate(expression));
    if (!tpl || el.children.length) return;
    A.mutateDom(() => {            // same mechanics as Alpine's own x-html
      el.innerHTML = tpl.innerHTML;
      el._x_ignoreSelf = true;
      A.initTree(el);
      delete el._x_ignoreSelf;
    });
  });
  // <pre class="vsm-xml-view" x-xml="xml" data-mark="terms">
  A.directive("xml", (el, { expression }, { evaluateLater, effect }) => {
    const get = evaluateLater(expression);
    effect(() => get(xml => {
      el.innerHTML = window.vsmXml.highlight(xml ?? "");
      if (el.dataset.mark) window.vsmXml.mark(el, el.dataset.mark.split(/\s+/));
    }));
  });

  A.store("app", {
    title: APP_TITLE,
    state: window.__vsmInitialState,
    route: parseRoute(),
    tick: 0,                       // bumped when overlay changes (catalog is non-reactive)
    engine: { state: engineStatus.state, error: "" },
    flash: "",
    busy: "",                      // text while building / loading engine
    sysmonVersions: S.SYSMON_VERSIONS,
    schemaFor: S.SCHEMA_FOR_VERSION,
    get upstream() { return vsm.upstream; },
    get catalog() { return vsm.catalog; },
    get fields() { return vsm.fields; },
    get profile() { return this.state.profiles[this.state.current]; },
    get profiles() { return Object.values(this.state.profiles); },
    get selected() { return new Set(this.profile?.modules || []); },
    get moduleTotal() { this.tick; return vsm.catalog.allRels().length; },
    get sidebar() {
      this.tick;
      const sel = this.selected;
      return vsm.catalog.categories().map(c => ({ cat: c, selected: c.modules.filter(m => sel.has(m.rel)).length, total: c.modules.length }));
    },
    get overlayRels() { this.tick; return vsm.catalog.overlayRels(); },

    persist() { if (this.profile) this.profile.updated = new Date().toISOString().slice(0, 19) + "Z"; S.saveState(A.raw(this.state)); },
    notify(msg) { this.flash = msg; clearTimeout(this._flashT); this._flashT = setTimeout(() => { this.flash = ""; }, 5000); },
    go(hash) { location.hash = hash; },
    // #/help/<section> – scroll the section into view (TOC links can't use plain #id with hash routing)
    scrollToSection() {
      const id = this.route.id;
      const el = id ? document.getElementById(id) : null;
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
      else if (!id) window.scrollTo(0, 0);
    },

    // ── profiles ──
    switchProfile(slug) { if (this.state.profiles[slug]) { this.state.current = slug; this.persist(); this.go("#/"); } },
    createProfile(name, mode, copyFrom) {
      const slug = S.slugify(name);
      if (this.state.profiles[slug]) throw new Error("Profile already exists");
      const src = copyFrom && this.state.profiles[copyFrom];
      const p = src ? { ...JSON.parse(JSON.stringify(A.raw(src))), slug, name: name.trim(), created: new Date().toISOString() }
        : S.newProfile(slug, name.trim(), { modules: mode === "all" ? vsm.catalog.allRels() : [] });
      this.state.profiles[slug] = p; this.state.current = slug; this.persist();
      return slug;
    },
    deleteProfile(slug) {
      delete this.state.profiles[slug]; delete this.state.builds[slug];
      if (this.state.current === slug) this.state.current = Object.keys(this.state.profiles)[0] || "";
      if (!this.state.current) S.ensureDefault(this.state, vsm.catalog);
      this.persist();
    },
    setModules(rels) { this.profile.modules = [...new Set(rels)].filter(r => vsm.catalog.exists(r)).sort(); this.persist(); },
    toggle(rel, on) { const s = this.selected; on ? s.add(rel) : s.delete(rel); this.setModules([...s]); },
    selectCategory(cat, mode) {
      const rels = vsm.catalog.moduleRels(cat), s = this.selected;
      if (mode === "all") rels.forEach(r => s.add(r));
      else if (mode === "none") rels.forEach(r => s.delete(r));
      else rels.filter(r => kindOf(r) === mode).forEach(r => s.add(r));
      this.setModules([...s]);
    },
    selectAll(mode) {
      const rels = vsm.catalog.allRels();
      this.setModules(mode === "all" ? rels : mode === "none" ? [] : rels.filter(r => kindOf(r) === mode));
    },
    importList(text, mode) {
      const rels = parseList(text, vsm.catalog);
      const s = this.selected;
      if (mode === "exclude") rels.forEach(r => s.delete(r));
      else if (mode === "add") rels.forEach(r => s.add(r));
      else { s.clear(); rels.forEach(r => s.add(r)); }
      this.setModules([...s]);
      return rels.length;
    },
    exportList() { download(`${this.profile.slug}_include_rules.txt`, formatList(this.profile, APP_TITLE), "text/plain"); },

    // ── overlay ──
    writeOverlay(rel, xml) { this.state.overlay[rel] = xml.endsWith("\n") ? xml : xml + "\n"; this.tick++; this.persist(); },
    revert(rel) {
      delete this.state.overlay[rel]; this.tick++;
      if (!vsm.catalog.exists(rel)) for (const p of Object.values(this.state.profiles)) p.modules = p.modules.filter(m => m !== rel);
      this.persist();
    },
    newModule(category, kind, name, eventType) {
      const rel = `${category}/${kind}_${moduleSlug(name)}.xml`;
      if (vsm.catalog.exists(rel)) throw new Error(`Module already exists: ${rel}`);
      this.writeOverlay(rel, toXml(emptyModule(eventType, kind, name, this.schemaFor[this.profile.sysmon_version] || "4.90")));
      this.toggle(rel, true);
      return rel;
    },
    duplicate(rel, name) {
      const [cat] = rel.split("/");
      const newRel = `${cat}/${kindOf(rel) === "exclude" ? "exclude" : "include"}_${moduleSlug(name)}.xml`;
      if (vsm.catalog.exists(newRel)) throw new Error(`Module already exists: ${newRel}`);
      this.writeOverlay(newRel, vsm.catalog.xml(rel));
      this.toggle(newRel, true);
      return newRel;
    },

    // ── export / import of the whole state ──
    exportAll() { download(`vsm-export-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(S.exportState(A.raw(this.state), vsm.upstream), null, 2), "application/json"); },
    async importAll(file, mode) {
      const data = JSON.parse(await file.text());
      const n = S.importState(this.state, data, mode);
      vsm.catalog.overlay = this.state.overlay;   // Catalog reads overlay by reference; replace mode swaps the object
      for (const p of Object.values(this.state.profiles)) S.normalizeProfile(p, vsm.catalog);
      this.tick++; this.persist();
      return n;
    },

    // ── engine ──
    modulesFor(rels) { return rels.map(rel => ({ path: rel, xml: vsm.catalog.xml(rel) })).filter(m => m.xml !== undefined); },
    async validateXml(rel, xml) {
      return engine.validate({ path: rel, xml, sysmonVersion: this.profile.sysmon_version, unsupported: this.profile.unsupported });
    },
    async coverageReport(rels) {
      if (!rels.length) return { ok: false, error: "The profile has no modules selected." };
      return engine.coverage({ modules: this.modulesFor(rels), format: "json" });
    },
    async navigatorLayer(rels, attackVersion) {
      const r = await engine.coverage({ modules: this.modulesFor(rels), format: "navigator", attackVersion, name: `${this.profile.name} – Sysmon coverage` });
      if (r.ok) download(`${this.profile.slug}-attack${attackVersion}-layer.json`, r.layer, "application/json");
      return r;
    },
    buildsFor(slug) { return this.state.builds[slug] || []; },
    build(id) { return (this.state.builds[this.state.current] || []).find(b => b.id === id); },
    async runBuild() {
      const p = this.profile;
      if (!p.modules.length) { this.notify("No modules selected."); return; }
      this.busy = engineStatus.state === "ready" ? "Merging modules…" : "Loading engine (one-time, ~4 MB)…";
      try {
        const modules = this.modulesFor(p.modules);
        const r = await engine.merge({ modules, template: vsm.catalog.template, sysmonVersion: p.sysmon_version, unsupported: p.unsupported,
          preserveComments: p.preserve_comments, forceGroupRelationOr: p.force_grouprelation_or, analyze: p.analyze });
        const findings = r.findings || [];
        let id = nowStamp();
        while (this.build(id)) id += "-x";
        const meta = {
          id, profile: p.slug, profile_name: p.name, sysmon_version: p.sysmon_version, schemaversion: r.schemaversion || this.schemaFor[p.sysmon_version],
          module_count: modules.length, group_count: r.groupCount || 0, ok: !!r.ok && !!r.xml, error: r.error || "",
          summary: summarize(findings), findings, warnings: r.warnings || [], output_size: r.xml ? r.xml.length : 0,
          coverage: null, diff: null, diff_before: null, created: new Date().toISOString(),
          include_list: formatList(p, APP_TITLE), upstream: vsm.upstream?.short || "",
        };
        if (meta.ok) {
          this.busy = "Computing coverage…";
          const c = await engine.coverage({ modules, format: "json" });
          if (c.ok) meta.coverage = c.report;
          const prev = this.buildsFor(p.slug).find(b => b.ok);
          if (prev) {
            const before = await S.getBuildXml(prev.id);
            if (before) {
              this.busy = "Comparing with previous build…";
              const d = await engine.diff({ before, after: r.xml });
              if (d.ok) { meta.diff = d.diff; meta.diff_before = prev.id; }
            }
          }
          await S.putBuildXml(id, r.xml);
        }
        const dropped = S.addBuild(this.state, p.slug, meta);
        if (dropped.length) S.deleteBuildXml(dropped);
        this.persist();
        this.go(`#/build/${id}`);
      } finally { this.busy = ""; }
    },
  });

  onEngineStatus(s => { const st = A.store("app"); st.engine.state = s.state; st.engine.error = s.error; });
  window.addEventListener("hashchange", () => {
    const route = parseRoute();
    A.store("app").route = route;
    if (!(route.page === "help" && route.id)) window.scrollTo(0, 0);   // help sections scroll themselves
  });

  // ── page components ──
  A.data("pageSearch", () => ({
    q: "", kind: "", category: "", scope: "selected", result: null,
    init() { this.q = this.$store.app.route.query.q || ""; this.run(); this.$watch("q", () => this.run()); this.$watch("kind", () => this.run()); this.$watch("category", () => this.run()); this.$watch("scope", () => this.run()); },
    run() {
      if (!this.q.trim() && !this.kind && !this.category) { this.result = null; return; }
      this.result = search(vsm.catalog, A.raw(this.$store.app.profile), { q: this.q, kind: this.kind, category: this.category, scope: this.scope });
    },
    newModule(i) { return i === 0 || this.result.hits[i].rel !== this.result.hits[i - 1].rel; },
    newCtx(i) { if (this.newModule(i)) return true; const a = this.result.hits[i], b = this.result.hits[i - 1]; return a.group_name !== b.group_name || a.event_type !== b.event_type || a.onmatch !== b.onmatch; },
    get mark() { return this.result ? this.result.terms.join(" ") : ""; },
  }));

  A.data("pageProfile", () => ({
    form: {}, newName: "", newMode: "all", copyFrom: "", importMode: "replace", stateImportMode: "replace",
    init() { const p = this.$store.app.profile; this.form = { name: p.name, description: p.description, sysmon_version: p.sysmon_version, unsupported: p.unsupported, analyze: p.analyze, preserve_comments: p.preserve_comments, force_grouprelation_or: p.force_grouprelation_or }; },
    save() { Object.assign(this.$store.app.profile, this.form, { name: this.form.name.trim() || this.$store.app.profile.name }); this.$store.app.persist(); this.$store.app.notify("Settings saved"); },
    create() { try { const slug = this.$store.app.createProfile(this.newName, this.newMode, this.copyFrom); this.newName = ""; this.$store.app.notify(`Profile '${slug}' created`); this.init(); } catch (e) { this.$store.app.notify(e.message); } },
    async importFile(ev) { const f = ev.target.files[0]; if (!f) return; const n = this.$store.app.importList(await f.text(), this.importMode); this.$store.app.notify(`${n} modules processed`); ev.target.value = ""; },
    async importState(ev) { const f = ev.target.files[0]; if (!f) return; try { const n = await this.$store.app.importAll(f, this.stateImportMode); this.$store.app.notify(`Imported ${n.profiles} profiles and ${n.overlay} overlay modules`); this.init(); } catch (e) { this.$store.app.notify(`Import failed: ${e.message}`); } ev.target.value = ""; },
    get builds() { return this.$store.app.buildsFor(this.$store.app.state.current).slice(0, 10); },
  }));

  A.data("pageCategory", () => ({
    q: "", kind: "", dupName: {},
    get cat() { this.$store.app.tick; return vsm.catalog.categories().find(c => c.dirname === this.$store.app.route.cat) || null; },
    get modules() {
      const q = this.q.trim().toLowerCase();
      return (this.cat?.modules || []).filter(m => (!this.kind || m.kind === this.kind) &&
        (!q || m.filename.toLowerCase().includes(q) || m.title.toLowerCase().includes(q) || m.techniques.some(t => t[0].toLowerCase().includes(q) || t[1].toLowerCase().includes(q))));
    },
    isOn(rel) { return this.$store.app.selected.has(rel); },
    duplicate(rel) { const name = (this.dupName[rel] || "").trim(); if (!name) return; try { const r = this.$store.app.duplicate(rel, name); this.$store.app.go(`#/m/${r}/edit`); } catch (e) { this.$store.app.notify(e.message); } },
    revert(m) { if (confirm(m.source === "custom" ? `Delete your custom module ${m.filename}?` : `Reset ${m.filename} to the upstream version?`)) { this.$store.app.revert(m.rel); this.$store.app.notify("Module reset"); } },
  }));

  A.data("pageNewModule", () => ({
    name: "", kind: "include", eventType: "",
    get cat() { return vsm.catalog.categories().find(c => c.dirname === this.$store.app.route.cat) || null; },
    init() { this.eventType = this.cat?.modules.flatMap(m => m.event_types)[0] || Object.keys(vsm.fields.events)[0]; },
    create() { try { const rel = this.$store.app.newModule(this.$store.app.route.cat, this.kind, this.name, this.eventType); this.$store.app.go(`#/m/${rel}/edit`); } catch (e) { this.$store.app.notify(e.message); } },
  }));

  A.data("pageEditor", () => ({
    model: null, m: null, error: "", dirty: false, saving: false, findings: null, hasErrors: false, status: "", xmlPreview: "",
    schema: vsm.fields, eventTypes: Object.keys(vsm.fields.events),
    init() {
      const rel = this.$store.app.route.rel;
      this.m = vsm.catalog.module(rel);
      if (!this.m) { this.error = "Module not found"; return; }
      try { this.model = parseModule(vsm.catalog.xml(rel)); } catch (e) { this.$store.app.go(`#/m/${rel}/raw`); this.$store.app.notify(`Cannot be parsed structurally: ${e.message}`); return; }
      const guard = e => { if (this.dirty) { e.preventDefault(); e.returnValue = ""; } };
      window.addEventListener("beforeunload", guard);
      this.$el.addEventListener("alpine:destroyed", () => window.removeEventListener("beforeunload", guard), { once: true });
    },
    fieldsFor(ev) { const e = this.schema.events[ev.event_type]; return e ? e.fields.filter(f => f !== "RuleName" && f !== "UtcTime") : []; },
    isMulti(c) { return this.schema.multi_value_conditions.includes(c.condition); },
    newCond(ev) { const fs = this.fieldsFor(ev); return { field: fs.includes("Image") ? "Image" : (fs[0] || ""), condition: "is", value: "", name: "" }; },
    newRule() { return { name: "", group_relation: "and", conditions: [] }; },
    addEvent(rg) { rg.events.push({ event_type: rg.events.length ? rg.events[rg.events.length - 1].event_type : this.eventTypes[0], onmatch: "include", conditions: [], rules: [] }); this.dirty = true; },
    addGroup() { this.model.rulegroups.push({ name: "", group_relation: "or", events: [] }); this.dirty = true; },
    async save(force) {
      this.saving = true; this.status = "";
      try {
        const model = JSON.parse(JSON.stringify(A.raw(this.model)));
        for (const rg of model.rulegroups) for (const ev of rg.events) if (!this.eventTypes.includes(ev.event_type)) throw new Error(`unknown event type ${ev.event_type}`);
        const xml = toXml(model);
        const r = await this.$store.app.validateXml(this.m.rel, xml);
        this.findings = r.findings || [];
        this.hasErrors = this.findings.some(f => f.severity === "error");
        if (this.hasErrors && !force) return;
        this.$store.app.writeOverlay(this.m.rel, xml);
        this.m = vsm.catalog.module(this.m.rel);
        this.dirty = false; this.status = "Saved to overlay."; this.xmlPreview = xml;
      } catch (e) { this.findings = [{ code: "APP", message: e.message, severity: "error", detail: "" }]; this.hasErrors = true; }
      finally { this.saving = false; }
    },
    findingsHtml() { return this.findings === null ? "" : renderFindings(this.findings); },
  }));

  A.data("pageRaw", () => ({
    m: null, xml: "", force: false, findings: null, parseError: "", busy: false, msg: "",
    init() { const rel = this.$store.app.route.rel; this.m = vsm.catalog.module(rel); this.xml = this.m ? vsm.catalog.xml(rel) : ""; this.$nextTick(() => window.vsmXml.init(this.$el)); },
    async validate() {
      this.busy = true; this.msg = "";
      const [ok, err] = isWellFormed(this.xml);
      this.parseError = ok ? "" : err;
      this.findings = ok ? (await this.$store.app.validateXml(this.m.rel, this.xml)).findings || [] : [];
      this.busy = false;
      return ok && !this.findings.some(f => f.severity === "error");
    },
    async save() {
      const clean = await this.validate();
      if (!clean && !this.force) { this.msg = "Not saved – fix the errors or choose 'Save anyway'."; return; }
      this.$store.app.writeOverlay(this.m.rel, this.xml);
      this.m = vsm.catalog.module(this.m.rel);
      this.msg = "Saved to overlay.";
    },
    findingsHtml() { return this.findings === null ? "" : renderFindings(this.findings, { summary: summarize(this.findings) }); },
  }));

  A.data("pageBuild", () => ({
    xml: null, diffHtml: "", diffBefore: "", tab: "findings",
    get b() { return this.$store.app.build(this.$store.app.route.id); },
    get grouped() { const g = {}; for (const s of SEVERITY_ORDER) g[s] = (this.b?.findings || []).filter(f => f.severity === s); return g; },
    get matrix() { return this.b?.coverage ? buildMatrix(this.b.coverage) : null; },
    get others() { return this.$store.app.buildsFor(this.$store.app.state.current).filter(x => x.ok && x.id !== this.b?.id); },
    sevLabel: s => SEV_LABEL[s],
    async init() {
      if (!this.b) return;
      this.diffBefore = this.b.diff_before || this.others[0]?.id || "";
      if (this.b.diff) this.diffHtml = renderDiff(this.b.diff, this.b.diff_before, this.b.id);
    },
    findingsHtml(list) { return renderFindings(list); },
    async loadXml() { if (this.xml === null) this.xml = (await S.getBuildXml(this.b.id)) || "(XML no longer stored)"; },
    async download() { const x = await S.getBuildXml(this.b.id); if (x) download(`sysmonconfig-${this.b.profile}-${this.b.id}.xml`, x, "application/xml"); else this.$store.app.notify("XML no longer stored for this build"); },
    async runDiff() {
      const before = await S.getBuildXml(this.diffBefore), after = await S.getBuildXml(this.b.id);
      if (!before || !after) { this.diffHtml = '<p class="text-muted">One of the builds has no stored XML.</p>'; return; }
      const d = await engine.diff({ before, after });
      this.diffHtml = d.ok ? renderDiff(d.diff, this.diffBefore, this.b.id) : `<div class="kc-callout kc-callout--danger"><span class="kc-callout-icon">✖</span><div><p class="kc-callout-body mb-0">${esc(d.error)}</p></div></div>`;
    },
    log() { const b = this.b; if (!b) return ""; return [`merge: ${b.module_count} modules → ${b.group_count} RuleGroups, target Sysmon ${b.sysmon_version} (schema ${b.schemaversion}), upstream ${b.upstream}`, ...(b.error ? [`error: ${b.error}`] : []), ...b.warnings.map(w => `warning: ${w}`), ...b.findings.map(f => `[${f.code}] ${f.severity}${f.line ? ` line ${f.line}` : ""}: ${f.message}${f.detail ? ` – ${f.detail}` : ""}`)].join("\n"); },
  }));

  A.data("pageCoverage", () => ({
    matrix: null, tagging: null, error: "", loading: true,
    async init() {
      const rels = this.$store.app.profile.modules;
      this.tagging = ruleTagging(vsm.catalog, rels);
      const r = await this.$store.app.coverageReport(rels);
      if (r.ok) this.matrix = buildMatrix(r.report); else this.error = r.error;
      this.loading = false;
    },
    async navigator(v) { const r = await this.$store.app.navigatorLayer(this.$store.app.profile.modules, v); if (!r.ok) this.$store.app.notify(r.error); else if (r.notes?.length) this.$store.app.notify(r.notes[0]); },
    json() { this.$store.app.coverageReport(this.$store.app.profile.modules).then(r => r.ok && download(`${this.$store.app.profile.slug}-coverage.json`, JSON.stringify(r.report, null, 2), "application/json")); },
  }));

  A.data("attackMatrix", () => ({
    q: "", showSubs: true, sel: null,
    matches(n) { const q = this.q.trim().toLowerCase(); return !q || n.hay.includes(q); },
    select(id) { this.sel = this.sel === id ? null : id; },
    current(matrix) { return this.sel ? matrix.byId[this.sel] : null; },
  }));
});

// ── routing ──────────────────────────────────────────────────────────────────
export function parseRoute(hash = location.hash) {
  const h = hash.replace(/^#\/?/, "");
  const [pathPart, queryPart] = h.split("?");
  const query = Object.fromEntries(new URLSearchParams(queryPart || ""));
  const seg = pathPart.split("/").filter(Boolean).map(decodeURIComponent);
  const r = { page: "search", cat: "", rel: "", id: "", query };
  if (!seg.length) return r;
  switch (seg[0]) {
    case "profile": r.page = "profile"; break;
    case "builds": r.page = "builds"; break;
    case "coverage": r.page = "coverage"; break;
    case "help": r.page = "help"; r.id = seg[1] || ""; break;
    case "c": r.page = "category"; r.cat = seg[1] || ""; break;
    case "new": r.page = "newModule"; r.cat = seg[1] || ""; break;
    case "build": r.page = "build"; r.id = seg[1] || ""; break;
    case "m": {
      const rel = seg.slice(1, 3).join("/");
      r.page = seg[3] === "raw" ? "raw" : "editor"; r.rel = validRel(rel) ? rel : "";
      break;
    }
    default: r.page = "search";
  }
  return r;
}
