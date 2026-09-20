import test from "node:test";
import assert from "node:assert/strict";
import { search } from "../../site/js/search.js";
import { newCatalog, profileWith } from "./helpers.mjs";

const catalog = newCatalog();
const all = profileWith(catalog.allRels());

test("catalog scans upstream", () => {
  assert.ok(catalog.categoryDirs().length >= 20);
  const m = catalog.module("1_process_creation/include_clear_windows_event_logs.xml");
  assert.equal(m.kind, "include"); assert.equal(m.source, "upstream"); assert.ok(m.event_types.includes("ProcessCreate"));
  assert.equal(catalog.module("1_process_creation/exclude_adobe_acrobat.xml").title, "Adobe acrobat");
});

test("overlay shadows upstream and custom modules appear", () => {
  const rel = "1_process_creation/include_clear_windows_event_logs.xml";
  const overlay = { [rel]: catalog.xml(rel).replace("wevtutil.exe", "example.exe"), "22_dns_query/exclude_mine.xml": catalog.xml("22_dns_query/exclude_ads.xml") };
  const c = newCatalog(overlay);
  assert.equal(c.sourceOf(rel), "edited");
  assert.equal(c.sourceOf("22_dns_query/exclude_mine.xml"), "custom");
  assert.ok(c.xml(rel).includes("example.exe"));
  assert.ok(c.moduleRels("22_dns_query").includes("22_dns_query/exclude_mine.xml"));
  assert.deepEqual(c.overlayRels(), [rel, "22_dns_query/exclude_mine.xml"]);
});

test("block hits with context", () => {
  const r = search(catalog, all, { q: "wevtutil" });
  assert.ok(r.total >= 1);
  const hit = r.hits.find(h => h.rel.endsWith("include_clear_windows_event_logs.xml"));
  assert.equal(hit.block, "rule"); assert.equal(hit.event_type, "ProcessCreate"); assert.ok(hit.xml.includes("wevtutil.exe"));
  assert.equal(hit.techniques[0][0], "T1685.005");
});

test("module-level hit when only the path matches", () => {
  const r = search(catalog, all, { q: "lsass_noise" });
  assert.equal(r.total, 1); assert.equal(r.hits[0].block, "module"); assert.ok(r.hits[0].xml.includes("<Sysmon"));
});

test("filters and scope", () => {
  const r = search(catalog, all, { q: "lsass", kind: "include", category: "10_process_access" });
  assert.ok(r.hits.length && r.hits.every(h => h.kind === "include" && h.category === "10_process_access"));
  const empty = profileWith([]);
  assert.equal(search(catalog, empty, { q: "wevtutil" }).total, 0);
  assert.ok(search(catalog, empty, { q: "wevtutil", scope: "all" }).total >= 1);
  const browse = search(catalog, all, { kind: "exclude", category: "22_dns_query" });
  assert.ok(browse.total > 0 && browse.hits.filter(h => h.block !== "module").every(h => h.onmatch === "exclude"));
});
