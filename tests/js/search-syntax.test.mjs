import test from "node:test";
import assert from "node:assert/strict";
import { search, parseQuery } from "../../site/js/search.js";
import { newCatalog, profileWith } from "./helpers.mjs";

const catalog = newCatalog();
const all = profileWith(catalog.allRels());

test("parseQuery", () => {
  const p = parseQuery('lsass -adobe onmatch:exclude event:10 field:TargetImage condition:"contains any" /ls.ss/ technique:T1003 "a b"');
  assert.deepEqual(p.filters, { onmatch: "exclude", event: "10", field: "targetimage", condition: "contains any", technique: "t1003" });
  assert.equal(p.terms.length, 4);
  assert.deepEqual(p.terms[0], { neg: false, text: "lsass" });
  assert.deepEqual(p.terms[1], { neg: true, text: "adobe" });
  assert.ok(p.terms[2].re instanceof RegExp && p.terms[2].re.test("LSASS"));
  assert.deepEqual(p.terms[3], { neg: false, text: "a b" });
  assert.ok(p.hasBlockFilter);
});

test("filters narrow modules and blocks", () => {
  const r = search(catalog, all, { q: "onmatch:include event:10 field:TargetImage lsass" });
  assert.ok(r.hits.length > 0);
  assert.ok(r.hits.every(h => h.onmatch === "include" && h.category === "10_process_access" && /TargetImage/.test(h.xml)));
  const ev = search(catalog, all, { q: "event:DnsQuery onmatch:exclude" });
  assert.ok(ev.total > 0 && ev.hits.every(h => h.event_type === "DnsQuery" && h.onmatch === "exclude"));
  const tech = search(catalog, all, { q: "technique:T1685.005" });
  assert.ok(tech.total >= 3 && tech.hits.every(h => h.techniques[0][0].startsWith("T1685.005")));
  const op = search(catalog, all, { q: 'condition:"contains any" wevtutil' });
  assert.ok(op.hits.length && op.hits.every(h => /contains any/.test(h.xml)));
});

test("negation and regex", () => {
  const base = search(catalog, all, { q: "event:22" }).total;
  const neg = search(catalog, all, { q: "event:22 -google" });
  assert.ok(neg.total < base && neg.hits.every(h => !/google/i.test(h.xml + h.rel)));
  const re = search(catalog, all, { q: "/wevt(util)?\\.exe/" });
  assert.ok(re.total >= 1 && re.hits.some(h => /wevtutil/.test(h.xml)));
  assert.ok(search(catalog, all, { q: "/[/" }).total >= 0); // invalid regex degrades to text
});

test("event id matching is exact", () => {
  const r1 = search(catalog, all, { q: "event:1" });
  assert.ok(r1.total > 0 && r1.module_rels.every(r => r.startsWith("1_process_creation/")));
  const r12 = search(catalog, all, { q: "event:12" });
  assert.ok(r12.total > 0 && r12.module_rels.every(r => r.startsWith("12_13_14_")));
  const rdns = search(catalog, all, { q: "event:dns" });
  assert.ok(rdns.total > 0 && rdns.module_rels.every(r => r.startsWith("22_dns_query/")));
  const rel = search(catalog, all, { q: "event:DnsQuery onmatch:exclude" });
  assert.ok(rel.total > 0 && rel.hits.every(h => h.event_type === "DnsQuery"));
});

test("module list for bulk actions", () => {
  const r = search(catalog, all, { q: "onmatch:exclude event:22" });
  assert.equal(r.module_rels.length, r.modules_hit);
  assert.ok(r.module_rels.every(m => m.startsWith("22_dns_query/exclude_")));
});
