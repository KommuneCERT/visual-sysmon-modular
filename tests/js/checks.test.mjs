import test from "node:test";
import assert from "node:assert/strict";
import { checklist, volumeOf, costOf, costTags } from "../../site/js/checks.js";
import { newCatalog } from "./helpers.mjs";

const catalog = newCatalog();
const all = catalog.allRels();
const titles = list => list.map(i => i.title);

test("cost map", () => {
  assert.equal(volumeOf("7_image_load").level, "high");
  assert.equal(volumeOf("8_create_remote_thread").level, "low");
  assert.deepEqual(costTags("7_image_load").map(t => t.key), ["cpu", "volume"]);
  assert.deepEqual(costTags("9_raw_access_read", { max: 1 }).map(t => t.key), ["cpu"]);
  assert.deepEqual(costTags("23_file_delete").map(t => t.key), ["disk", "volume"]);
  assert.deepEqual(costTags("24_clipboard_change").map(t => t.key), ["privacy"]);
  assert.deepEqual(costTags("5_process_ended"), []);
  assert.ok(costOf("9_raw_access_read").why.includes("OFF"));
});

test("RawAccessRead include with conditions is flagged", () => {
  const rel = "9_raw_access_read/include_dc_full.xml";
  const c = newCatalog({ [rel]: '<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="" groupRelation="or"><RawAccessRead onmatch="include"><Device condition="contains">Harddisk</Device></RawAccessRead></RuleGroup></EventFiltering></Sysmon>' });
  const t = titles(checklist(c, { modules: [rel, ...all.filter(r => !r.startsWith("9_"))], sysmon_version: "15.20", unsupported: "exclude" }, null));
  assert.ok(t.includes("RawAccessRead (event 9) is active"));
  const t2 = titles(checklist(catalog, { modules: all, sysmon_version: "15.20", unsupported: "exclude" }, null));
  assert.ok(!t2.includes("RawAccessRead (event 9) is active"), "upstream's empty filter must not warn");
});

test("empty and exclude-only selections", () => {
  assert.equal(checklist(catalog, { modules: [], sysmon_version: "15", unsupported: "warn" }, null)[0].level, "error");
  const exclOnly = { modules: all.filter(r => r.includes("/exclude_")), sysmon_version: "15", unsupported: "exclude" };
  const t = titles(checklist(catalog, exclOnly, null));
  assert.ok(t.includes("Only exclusion modules are selected"));
  assert.ok(t.some(x => x.startsWith("7_image_load: exclude-only")));
});

test("high-volume category without exclusions, filedelete, version, build state", () => {
  const p = { modules: all.filter(r => !(r.startsWith("7_image_load/") && r.includes("/exclude_"))), sysmon_version: "13", unsupported: "warn", updated: "2026-09-20T10:00:00Z" };
  const t = titles(checklist(catalog, p, null));
  assert.ok(t.includes("7_image_load: no noise exclusions selected"));
  const fdItem = checklist(catalog, p, null).find(i => i.title.startsWith("FileDelete archiving (event 23) is on"));
  assert.ok(fdItem && fdItem.level === "warn" && /C:\\Sysmon/.test(fdItem.detail));
  assert.ok(volumeOf("23_file_delete").disk);
  assert.ok(t.includes("Target Sysmon 13 with unsupported items kept"));
  assert.ok(t.includes("Not built yet"));
  const built = checklist(catalog, p, { id: "b", ok: true, created: "2026-09-20T09:00:00Z", summary: { error: 0, warning: 2 }, findings: [{ code: "ANL006" }, { code: "ANL006" }] });
  const tb = titles(built);
  assert.ok(tb.includes("Profile changed after the last build"));
  assert.ok(tb.includes("2 exclusions match by bare image name"));
  assert.ok(tb.includes("2 warnings in the last build"));
  assert.ok(!tb.includes("Not built yet"));
  const bad = checklist(catalog, p, { id: "b", ok: false, created: "2026-09-21T09:00:00Z", summary: { error: 1 }, findings: [] });
  assert.equal(bad.find(i => i.level === "error").title, "The last build has errors");
});
