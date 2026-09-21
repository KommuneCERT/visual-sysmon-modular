// Visual Sysmon Modular – static, search-first SPA. Alpine store + page components.
import { Catalog, slugify as moduleSlug, validRel, kindOf } from "./catalog.js";
import { parseModule, toXml, emptyModule, isWellFormed } from "./model.js";
import * as S from "./state.js";
import { engine, engineStatus, onEngineStatus } from "./engine.js";
import { search } from "./search.js";
import { buildMatrix, ruleTagging } from "./attack.js";
import { parseList, formatList } from "./includelist.js";
import { describeRule, describeBare, describeHit } from "./describe.js";
import { checklist, costOf, costTags } from "./checks.js";

export const APP_TITLE = "Visual Sysmon Modular";
const SEVERITY_ORDER = ["error", "warning", "performance", "recommendation", "info"];

// Non-reactive globals (large / immutable). The reactive store only holds user state.
export const vsm = { catalog: null, fields: null, upstream: null, attack: null, attackById: {} };

// ── boot: fetch data, then start Alpine ──────────────────────────────────────
async function boot() {
  const [catalogData, fields, upstream, attack] = await Promise.all(
    ["data/catalog.json", "data/fields.json", "data/upstream.json", "data/attack.json"].map(u => fetch(u).then(r => { if (!r.ok) throw new Error(`${u}: ${r.status}`); return r.json(); })));
  vsm.attack = attack;
  vsm.attackById = Object.fromEntries(attack.techniques.map(t => [t.id, t]));
  const state = S.loadState();
  vsm.catalog = new Catalog(catalogData, state.overlay);
  vsm.fields = fields;
  vsm.upstream = upstream;
  S.ensureDefault(state, vsm.catalog);
  // single implicit configuration: whatever profile is current becomes "the" configuration
  if (state.current !== "default" && state.profiles[state.current]) { state.profiles.default = { ...state.profiles[state.current], slug: "default" }; }
  state.current = "default";
  for (const slug of Object.keys(state.profiles)) if (slug !== "default") delete state.profiles[slug];
  delete state.builds;
  S.normalizeProfile(state.profiles.default, vsm.catalog);
  S.saveState(state);
  return state;
}

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
  // <span x-pop="'text'"> – popover on hover/focus for any element (badges, dots)
  A.directive("pop", (el, { expression }, { evaluate }) => {
    el.setAttribute("tabindex", "0");
    new window.bootstrap.Popover(el, { content: evaluate(expression), html: true, trigger: "hover focus", placement: "right" });
  });
  // <button x-copy="text"> copies to the clipboard and flashes "Copied"
  A.directive("copy", (el, { expression }, { evaluateLater }) => {
    const get = evaluateLater(expression);
    el.addEventListener("click", () => get(async text => {
      try { await navigator.clipboard.writeText(text); } catch { return; }
      const old = el.textContent; el.textContent = "Copied ✓"; setTimeout(() => { el.textContent = old; }, 1500);
    }));
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
    busy: "",
    lastQuery: "",
    dl: null,                      // result of the last merge for the download modal
    importMode: "replace",
    sysmonTargets: S.SYSMON_TARGETS,
    schemaFor: S.SCHEMA_FOR_VERSION,
    get upstream() { return vsm.upstream; },
    get catalog() { return vsm.catalog; },
    get fields() { return vsm.fields; },
    get profile() { return this.state.profiles.default; },
    get selected() { return new Set(this.profile.modules); },
    get moduleTotal() { this.tick; return vsm.catalog.allRels().length; },
    get overlayRels() { this.tick; return vsm.catalog.overlayRels(); },
    get hasQuery() { return !!(this.route.query.q || "").trim() || !!this.lastQuery.trim(); },
    get searchHref() { return this.lastQuery ? `#/?q=${encodeURIComponent(this.lastQuery)}` : "#/"; },
    get pageTitle() { return ({ search: "Search", editor: "Rule editor", raw: "Raw XML", newModule: "New module", coverage: "ATT&CK coverage", help: "Help" })[this.route.page] || ""; },
    // "of 441" would suggest a deviation – the standard itself uses 433 of upstream's 441 modules (no FileDelete archiving)
    get statusLine() { this.tick; const n = this.changeCount; return n ? `${this.selected.size} modules · ${n} change${n === 1 ? "" : "s"} from standard` : `Standard configuration · ${this.selected.size} modules`; },
    get dlChecklist() { return this.dl ? checklist(vsm.catalog, A.raw(this.profile), this.dl.meta) : []; },
    // differences from the standard configuration, for the "Your changes" panel
    get changes() {
      this.tick;
      const std = new Set((vsm.catalog.presets.find(p => p.id === "balanced") || { modules: vsm.catalog.allRels() }).modules);
      const sel = this.selected;
      const mod = rel => vsm.catalog.module(rel);
      return {
        edited: this.overlayRels.filter(r => vsm.catalog.sourceOf(r) === "edited").map(mod),
        custom: this.overlayRels.filter(r => vsm.catalog.sourceOf(r) === "custom").map(mod),
        off: [...std].filter(r => !sel.has(r) && vsm.catalog.exists(r)).sort().map(mod),
        on: [...sel].filter(r => !std.has(r) && vsm.catalog.sourceOf(r) !== "custom").sort().map(mod),
      };
    },
    get changeCount() { const c = this.changes; return c.edited.length + c.custom.length + c.off.length + c.on.length; },
    showChanges() { new window.bootstrap.Modal(document.getElementById("changes")).show(); },
    volumeOf: cat => { const c = costOf(cat); return { level: c.volume, disk: c.disk === "high", why: c.why }; },
    costOf, costTags,

    persist(touch = true) { if (touch) this.profile.updated = new Date().toISOString(); S.saveState(A.raw(this.state)); },
    notify(msg) { this.flash = msg; clearTimeout(this._flashT); this._flashT = setTimeout(() => { this.flash = ""; }, 5000); },
    go(hash) { location.hash = hash; },
    scrollToSection() {
      const id = this.route.id;
      const el = id ? document.getElementById(id) : null;
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
      else if (!id) window.scrollTo(0, 0);
    },

    // ── configuration (single implicit profile) ──
    setModules(rels) { this.profile.modules = [...new Set(rels)].filter(r => vsm.catalog.exists(r)).sort(); this.persist(); },
    toggle(rel, on) { const s = this.selected; on ? s.add(rel) : s.delete(rel); this.setModules([...s]); },
    setTarget(v) { if (S.SYSMON_VERSIONS.includes(v)) { this.profile.sysmon_version = v; this.persist(); } },
    importList(text, mode) {
      const rels = parseList(text, vsm.catalog), s = this.selected;
      if (mode === "exclude") rels.forEach(r => s.delete(r)); else if (mode === "add") rels.forEach(r => s.add(r)); else { s.clear(); rels.forEach(r => s.add(r)); }
      this.setModules([...s]); return rels.length;
    },
    exportList() { download("include_rules.txt", formatList(this.profile, APP_TITLE), "text/plain"); },
    resetToStandard() {
      const edits = this.overlayRels.length;
      if (!confirm(`Reset to sysmon-modular's standard configuration?\n\nThis restores the standard module selection and discards ${edits} edited/custom module(s). Export first if you want to keep them.`)) return;
      const balanced = vsm.catalog.presets.find(p => p.id === "balanced");
      for (const rel of Object.keys(this.state.overlay)) delete this.state.overlay[rel];
      this.setModules(balanced ? balanced.modules : vsm.catalog.allRels());
      this.tick++; this.persist(); this.notify("Standard configuration restored");
    },

    // ── overlay ──
    writeOverlay(rel, xml) { this.state.overlay[rel] = xml.endsWith("\n") ? xml : xml + "\n"; this.tick++; this.persist(); },
    revert(rel) {
      delete this.state.overlay[rel]; this.tick++;
      if (!vsm.catalog.exists(rel)) this.profile.modules = this.profile.modules.filter(m => m !== rel);
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

    // ── export / import ──
    exportAll() { download(`vsm-export-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(S.exportState(A.raw(this.state), vsm.upstream), null, 2), "application/json"); },
    async importAll(file, mode) {
      const data = JSON.parse(await file.text());
      const n = S.importState(this.state, data, mode);
      // collapse to the single implicit configuration
      const pick = this.state.profiles[data.current] || this.state.profiles.default || Object.values(this.state.profiles)[0];
      if (pick) this.state.profiles.default = { ...pick, slug: "default" };
      for (const slug of Object.keys(this.state.profiles)) if (slug !== "default") delete this.state.profiles[slug];
      this.state.current = "default";
      vsm.catalog.overlay = this.state.overlay;
      S.normalizeProfile(this.profile, vsm.catalog);
      this.tick++; this.persist();
      return n;
    },
    async importFromInput(ev) {
      const f = ev.target.files[0]; if (!f) return;
      try { const n = await this.importAll(f, this.importMode); this.notify(`Imported ${n.profiles ? "configuration" : "nothing"}${n.overlay ? ` and ${n.overlay} edited modules` : ""}`); }
      catch (e) { this.notify(`Import failed: ${e.message}`); }
      ev.target.value = "";
    },

    // ── engine ──
    modulesFor(rels) { return rels.map(rel => ({ path: rel, xml: vsm.catalog.xml(rel) })).filter(m => m.xml !== undefined); },
    async validateXml(rel, xml) { return engine.validate({ path: rel, xml, sysmonVersion: this.profile.sysmon_version, unsupported: "exclude" }); },
    async coverageReport(rels) {
      if (!rels.length) return { ok: false, error: "No modules are switched on." };
      return engine.coverage({ modules: this.modulesFor(rels), format: "json" });
    },
    async navigatorLayer(rels, attackVersion) {
      const r = await engine.coverage({ modules: this.modulesFor(rels), format: "navigator", attackVersion, name: "Sysmon coverage" });
      if (r.ok) download(`sysmon-attack${attackVersion}-layer.json`, r.layer, "application/json");
      return r;
    },

    // ── download = merge + modal ──
    async download() {
      const p = this.profile;
      if (!p.modules.length) { this.notify("No modules are switched on."); return; }
      this.busy = engineStatus.state === "ready" ? "Merging modules…" : "Loading engine (one-time, ~4 MB)…";
      try {
        const modules = this.modulesFor(p.modules);
        const r = await engine.merge({ modules, template: vsm.catalog.template, sysmonVersion: p.sysmon_version, unsupported: "exclude",
          preserveComments: true, forceGroupRelationOr: false, analyze: true });
        const findings = r.findings || [];
        const summary = summarize(findings);
        const ok = !!r.ok && !!r.xml;
        this.dl = {
          ok, xml: r.xml || "", error: ok ? "" : (r.error || "The merge reported errors – fix them before downloading."),
          summary, findings, findingsHtml: renderFindings(findings),
          title: `${modules.length} modules · Sysmon ${p.sysmon_version} (schema ${r.schemaversion || this.schemaFor[p.sysmon_version]})${r.groupCount ? ` · ${r.groupCount} RuleGroups` : ""}`,
          meta: { id: "now", ok, created: new Date().toISOString(), summary, findings },
        };
        new window.bootstrap.Modal(document.getElementById("dl")).show();
      } finally { this.busy = ""; }
    },
    saveDownload() {
      if (!this.dl?.ok) return;
      download("sysmonconfig.xml", this.dl.xml, "application/xml");
      window.bootstrap.Modal.getInstance(document.getElementById("dl"))?.hide();
    },

    // ── help tables ──
    fillHelpTables(root) {
      const cost = root.querySelector("#cost-table tbody");
      const lvl = v => `<span class="vsm-cost-dim vsm-cost-${v || "low"}">${v || "low"}</span>`;
      if (cost) cost.innerHTML = vsm.catalog.categories().map(c => { const k = costOf(c.dirname); return `<tr><td><a href="#/?q=event:${c.event_ids[0]}">${c.event_ids.join("/")} ${esc(c.label)}</a></td><td>${lvl(k.volume)}</td><td>${lvl(k.cpu)}</td><td>${lvl(k.disk)}${k.privacy === "high" ? ' <span class="vsm-cost-dim vsm-cost-high">privacy</span>' : ""}</td><td class="small">${esc(k.why)}</td></tr>`; }).join("");
      const ev = root.querySelector("#event-table tbody");
      const sel = this.selected;
      if (ev) ev.innerHTML = vsm.catalog.categories().map(c => {
        const on = c.modules.filter(m => sel.has(m.rel)).length, inc = c.modules.filter(m => m.kind === "include").length;
        const tags = costTags(c.dirname).map(t => `<span class="${t.cls}">${t.label}</span>`).join(" ");
        return `<tr><td><span class="vsm-evid">${c.event_ids.join("/")}</span></td><td>${esc(c.label)} ${tags}</td><td>${on} / ${c.modules.length}</td><td class="small">${inc} include · ${c.modules.length - inc} exclude</td><td><a href="#/?q=event:${c.event_ids[0]}">search</a> · <a href="#/new?cat=${c.dirname}">new module</a></td></tr>`;
      }).join("");
    },
  });

  // ── keyboard shortcuts (ignored while typing) ──
  const SHORTCUTS = { "/": "search", "d": "download", "c": "#/coverage", "h": "#/help", "?": "#/help/shortcuts" };
  document.addEventListener("keydown", e => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) { if (e.key === "Escape") t.blur(); return; }
    if (document.querySelector(".modal.show")) return;
    const action = SHORTCUTS[e.key];
    if (!action) return;
    e.preventDefault();
    const st = A.store("app");
    if (action === "download") st.download();
    else if (action === "search") { if (st.route.page !== "search") st.go(st.searchHref); setTimeout(() => document.getElementById("q")?.focus(), 150); }
    else st.go(action);
  });

  onEngineStatus(s => { const st = A.store("app"); st.engine.state = s.state; st.engine.error = s.error; });
  window.addEventListener("hashchange", () => {
    const route = parseRoute();
    A.store("app").route = route;
    if (!(route.page === "help" && route.id)) window.scrollTo(0, 0);
  });

  // ── page components ──
  A.data("pageSearch", () => ({
    q: "", scope: "selected", result: null,
    init() {
      this.q = this.$store.app.route.query.q || this.$store.app.lastQuery || "";
      this.run();
      this.$watch("q", () => { this.$store.app.lastQuery = this.q; this.run(); });
      this.$watch("scope", () => this.run());
      this.$watch("$store.app.route.query.q", v => { if (v !== undefined && v !== this.q) this.q = v; });
      this.$nextTick(() => document.getElementById("q")?.focus());
    },
    run() {
      if (!this.q.trim()) { this.result = null; return; }
      this.result = search(vsm.catalog, A.raw(this.$store.app.profile), { q: this.q, scope: this.scope });
    },
    get singleCategory() {
      if (!this.result) return "";
      const cats = new Set(this.result.module_rels.map(r => r.split("/")[0]));
      return cats.size === 1 ? [...cats][0] : "";
    },
    newModule(i) { return i === 0 || this.result.hits[i].rel !== this.result.hits[i - 1].rel; },
    newCtx(i) { if (this.newModule(i)) return true; const a = this.result.hits[i], b = this.result.hits[i - 1]; return a.group_name !== b.group_name || a.event_type !== b.event_type || a.onmatch !== b.onmatch; },
    get mark() { return this.result ? this.result.terms.join(" ") : ""; },
    sentence(hit) { return describeHit(hit); },
    // keep the hit list stable while toggling – only the flag changes until the next search
    toggleHit(hit, on) { this.$store.app.toggle(hit.rel, on); for (const h of this.result.hits) if (h.rel === hit.rel) h.selected = on; },
    bulk(on) {
      if (!this.result) return;
      const s = this.$store.app.selected;
      for (const rel of this.result.module_rels) on ? s.add(rel) : s.delete(rel);
      this.$store.app.setModules([...s]);
      this.$store.app.notify(`${this.result.module_rels.length} modules switched ${on ? "on" : "off"}`);
      for (const h of this.result.hits) h.selected = on;
    },
  }));

  A.data("pageNewModule", () => ({
    name: "", kind: "include", eventType: "", category: "",
    get categories() { return vsm.catalog.categories(); },
    init() { this.category = this.$store.app.route.query.cat && this.categories.some(c => c.dirname === this.$store.app.route.query.cat) ? this.$store.app.route.query.cat : this.categories[0].dirname; this.pickEvent(); },
    pickEvent() { const c = this.categories.find(x => x.dirname === this.category); this.eventType = c?.modules.flatMap(m => m.event_types)[0] || Object.keys(vsm.fields.events)[0]; },
    create() { try { const rel = this.$store.app.newModule(this.category, this.kind, this.name, this.eventType); this.$store.app.go(`#/m/${rel}/edit`); } catch (e) { this.$store.app.notify(e.message); } },
  }));

  A.data("pageEditor", () => ({
    model: null, m: null, error: "", dirty: false, saving: false, findings: null, hasErrors: false, status: "", xmlPreview: "",
    explain: (() => { try { return localStorage.getItem("vsm.explain") !== "0"; } catch { return true; } })(),
    toggleExplain() { this.explain = !this.explain; try { localStorage.setItem("vsm.explain", this.explain ? "1" : "0"); } catch { /* ignore */ } },
    explainRule(ev, r) { return `${ev.onmatch === "exclude" ? "Ignore" : "Log"} ${ev.event_type} when ${describeRule(r)}`; },
    explainBare(rg, ev) { return `${ev.onmatch === "exclude" ? "Ignore" : "Log"} ${ev.event_type} when ${describeBare(ev.conditions, rg.group_relation)}`; },
    schema: vsm.fields, eventTypes: Object.keys(vsm.fields.events),
    init() {
      this.load();
      this.$watch("$store.app.route.rel", () => { this.findings = null; this.hasErrors = false; this.status = ""; this.xmlPreview = ""; this.dirty = false; this.load(); });
    },
    load() {
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
        // schemaversion is the module file's own declaration; raise it to what the events used require
        // (the merged output always gets the profile's target schema regardless)
        const need = model.rulegroups.flatMap(rg => rg.events.map(ev => this.schema.events[ev.event_type]?.min_schema || "4.00"));
        model.schemaversion = [model.schemaversion || "4.90", ...need].sort((a, b) => cmpVer(a, b)).pop();
        this.model.schemaversion = model.schemaversion;
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
    init() { this.load(); this.$watch("$store.app.route.rel", () => { this.findings = null; this.parseError = ""; this.msg = ""; this.load(); }); },
    load() { const rel = this.$store.app.route.rel; this.m = vsm.catalog.module(rel); this.xml = this.m ? vsm.catalog.xml(rel) : ""; this.$nextTick(() => { window.vsmXml.init(this.$el); this.$el.querySelector("textarea")?.dispatchEvent(new Event("input")); }); },
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

  // Autocomplete for technique_id=…,technique_name=… on Rule / RuleGroup name inputs.
  A.data("techPicker", ({ get, set }) => ({
    open: false, sel: 0, items: [],
    getValue: get, setValue: set,
    query(v) {
      const q = (v || "").replace(/^technique_id=/i, "").replace(/,technique_name=.*$/i, "").trim().toLowerCase();
      if (q.length < 2) { this.items = []; this.open = false; return; }
      const all = vsm.attack.techniques;
      const starts = [], contains = [];
      for (const t of all) {
        if (t.revoked || t.deprecated) continue;
        const idl = t.id.toLowerCase(), name = (t.full || t.name).toLowerCase();
        if (idl.startsWith(q)) starts.push(t); else if (name.includes(q) || idl.includes(q)) contains.push(t);
        if (starts.length + contains.length > 60) break;
      }
      this.items = [...starts, ...contains].slice(0, 8); this.sel = 0; this.open = this.items.length > 0;
    },
    tag(t) { return `technique_id=${t.id},technique_name=${t.name}`; },
    choose(t) { this.setValue(this.tag(t)); this.open = false; },
    key(e) {
      if (!this.open) return;
      if (e.key === "ArrowDown") { e.preventDefault(); this.sel = (this.sel + 1) % this.items.length; }
      else if (e.key === "ArrowUp") { e.preventDefault(); this.sel = (this.sel - 1 + this.items.length) % this.items.length; }
      else if (e.key === "Enter") { e.preventDefault(); this.choose(this.items[this.sel]); }
      else if (e.key === "Escape") { this.open = false; }
    },
    status(v) {   // ✓ known & name matches · ✗ unknown · ~ name differs · ⚠ revoked
      const m = /technique_id=([^,]+),technique_name=(.*)$/.exec(v || "");
      if (!m) return v && /technique/i.test(v) ? { cls: "kc-tag-red", text: "malformed tag", title: "Expected technique_id=T####[.###],technique_name=…" } : null;
      const t = vsm.attackById[m[1].trim()];
      if (!t) return { cls: "kc-tag-red", text: "unknown ID", title: `${m[1]} is not in the ATT&CK table` };
      if (t.revoked || t.deprecated) return { cls: "kc-tag-amber", text: t.revoked ? "revoked" : "deprecated", title: t.replacement ? `Replaced by ${t.replacement}` : "No replacement" };
      const want = m[2].trim().toLowerCase();
      const ok = [t.name, t.full, t.full?.replace(": ", " - ")].filter(Boolean).some(n => n.toLowerCase() === want);
      return ok ? { cls: "kc-tag-green", text: "ATT&CK ✓", title: (t.full || t.name) + " · " + t.tactics.join(", ") } : { cls: "kc-tag-amber", text: "name differs", title: `ATT&CK name: ${t.name}` };
    },
  }));


  A.data("attackMatrix", () => ({
    q: "", showSubs: true, sel: null,
    matches(n) { const q = this.q.trim().toLowerCase(); return !q || n.hay.includes(q); },
    select(id) { this.sel = this.sel === id ? null : id; },
    current(matrix) { return this.sel ? matrix.byId[this.sel] : null; },
  }));
});

function cmpVer(a, b) {
  const pa = String(a).split(".").map(Number), pb = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; }
  return 0;
}

// ── routing ──────────────────────────────────────────────────────────────────
export function parseRoute(hash = location.hash) {
  const h = hash.replace(/^#\/?/, "");
  const [pathPart, queryPart] = h.split("?");
  const query = Object.fromEntries(new URLSearchParams(queryPart || ""));
  const seg = pathPart.split("/").filter(Boolean).map(decodeURIComponent);
  const r = { page: "search", rel: "", id: "", query };
  if (!seg.length) return r;
  switch (seg[0]) {
    case "coverage": r.page = "coverage"; break;
    case "help": r.page = "help"; r.id = seg[1] || ""; break;
    case "new": r.page = "newModule"; break;
    case "m": {
      const rel = seg.slice(1, 3).join("/");
      r.page = seg[3] === "raw" ? "raw" : "editor"; r.rel = validRel(rel) ? rel : "";
      break;
    }
    default: r.page = "search";
  }
  return r;
}
