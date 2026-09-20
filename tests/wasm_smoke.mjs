// Smoke test for the WASM engine, run with: node tests/wasm_smoke.mjs
// Loads site/wasm/sysmon-modular.wasm through Go's wasm_exec.js and exercises every export.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import assert from "node:assert/strict";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const site = path.join(root, "site");

// wasm_exec.js expects browser-ish globals; Node has crypto/performance/TextEncoder built in.
globalThis.require = (await import("node:module")).createRequire(import.meta.url);
await import(path.join(site, "js/vendor/wasm_exec.js"));

const go = new globalThis.Go();
const ready = new Promise(r => { globalThis.__sysmonModularReady = r; });
const { instance } = await WebAssembly.instantiate(readFileSync(path.join(site, "wasm/sysmon-modular.wasm")), go.importObject);
go.run(instance);
await ready;
const api = globalThis.sysmonModular;

const catalog = JSON.parse(readFileSync(path.join(site, "data/catalog.json"), "utf8"));
const byRel = Object.fromEntries(catalog.modules.map(m => [m.rel, m.xml]));
const pick = rels => rels.map(rel => ({ path: rel, xml: byRel[rel] }));

// version
assert.equal(api.version().ok, true);

// merge two modules
const r = api.merge({ modules: pick(["1_process_creation/include_clear_windows_event_logs.xml", "5_process_ended/include_security_process_termination.xml"]), sysmonVersion: "15", analyze: true });
assert.equal(r.ok, true, JSON.stringify(r.findings));
assert.match(r.xml, /^<Sysmon schemaversion="4.90">/);
assert.ok(r.xml.includes("wevtutil.exe") && r.xml.includes("<ProcessTerminate"));
assert.equal(r.groupCount, 2);
assert.ok(Array.isArray(r.findings));

// template from upstream is honoured
const t = api.merge({ modules: pick(["22_dns_query/exclude_ads.xml"]), template: catalog.template, sysmonVersion: "12", unsupported: "exclude" });
assert.equal(t.ok, true);
assert.match(t.xml, /schemaversion="4.40"/);
assert.ok(t.xml.includes("<HashAlgorithms>*</HashAlgorithms>"));

// full merge of every module – no errors, many groups
const all = api.merge({ modules: pick(catalog.modules.map(m => m.rel)), sysmonVersion: "15", analyze: true });
assert.equal(all.ok, true, JSON.stringify(all.findings.filter(f => f.severity === "error").slice(0, 3)));
assert.ok(all.groupCount > 400, `groupCount ${all.groupCount}`);
assert.ok(all.findings.some(f => f.code.startsWith("ANL")), "analyzer findings expected");

// validate: good and bad
const good = api.validate({ path: "x.xml", xml: byRel["1_process_creation/include_clear_windows_event_logs.xml"], sysmonVersion: "15" });
assert.equal(good.ok, true);
const bad = api.validate({ path: "bad.xml", xml: '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="x" groupRelation="or"><ProcessCreate onmatch="include"><Bogus condition="is">a</Bogus><Rule name="technique_id=T9999,technique_name=x"><Image condition="is"></Image></Rule></ProcessCreate></RuleGroup></EventFiltering></Sysmon>', sysmonVersion: "15" });
assert.equal(bad.ok, false);
assert.ok(bad.findings.some(f => f.code === "SYS202" && f.severity === "error"));
assert.ok(bad.findings.some(f => f.code === "MITRE_UNKNOWN_ID"));
const broken = api.validate({ path: "b.xml", xml: "<Sysmon><broken" });
assert.equal(broken.findings[0].code, "XML001");

// coverage json + navigator
const cov = api.coverage({ modules: pick(["1_process_creation/include_clear_windows_event_logs.xml", "10_process_access/include_lsass_access.xml"]) });
assert.equal(cov.ok, true);
assert.ok(cov.report.techniques.some(t => t.id === "T1003"), "T1003 expected");
assert.ok(cov.report.techniques[0].tactics.length > 0);
const nav = api.coverage({ modules: pick(["1_process_creation/include_clear_windows_event_logs.xml"]), format: "navigator", attackVersion: "18" });
assert.equal(nav.ok, true);
assert.equal(JSON.parse(nav.layer).domain, "enterprise-attack");
assert.ok(nav.notes.length >= 1, "v18 remap note expected for T1685.005");

// diff
const d = api.diff({ before: r.xml, after: t.xml });
assert.equal(d.ok, true);
assert.ok(d.diff.changes.length > 0 && d.diff.summary);

// format
const f = api.format({ xml: "<Sysmon schemaversion=\"4.90\"><EventFiltering><RuleGroup name=\"a\"><ProcessCreate onmatch=\"include\"><Image condition=\"is\">x</Image></ProcessCreate></RuleGroup></EventFiltering></Sysmon>" });
assert.equal(f.ok, true);
assert.ok(f.xml.includes("\n  <EventFiltering>"));

console.log(`wasm smoke OK – ${catalog.modules.length} modules, ${all.groupCount} groups, ${all.findings.length} findings on full merge, wasm ${(readFileSync(path.join(site, "wasm/sysmon-modular.wasm")).length / 1e6).toFixed(1)} MB`);
process.exit(0);
