import test from "node:test";
import assert from "node:assert/strict";
import * as S from "../../site/js/state.js";
import { parseList, formatList } from "../../site/js/includelist.js";
import { buildMatrix, ruleTagging } from "../../site/js/attack.js";
import { newCatalog, profileWith } from "./helpers.mjs";

const catalog = newCatalog();

test("default profile, export and import roundtrip", () => {
  const state = S.ensureDefault(S.emptyState(), catalog);
  assert.equal(state.current, "default");
  assert.equal(state.profiles.default.preset, "balanced");
  assert.equal(state.profiles.default.modules.length, catalog.presets.find(p => p.id === "balanced").modules.length);
  assert.equal(state.profiles.default.unsupported, "exclude");
  state.overlay["22_dns_query/exclude_mine.xml"] = "<Sysmon/>";
  const exp = S.exportState(state, { commit: "abc", date: "2026-09-18" });
  assert.equal(exp.format, 1);
  const fresh = S.emptyState();
  const n = S.importState(fresh, JSON.parse(JSON.stringify(exp)), "replace");
  assert.deepEqual(n, { profiles: 1, overlay: 1 });
  assert.deepEqual(fresh.profiles.default.modules, state.profiles.default.modules);
  assert.throws(() => S.importState(fresh, { hello: 1 }), /not a Visual Sysmon Modular export/);
});

test("localStorage persistence uses a pluggable storage", () => {
  const mem = new Map();
  const storage = { getItem: k => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, v) };
  const state = S.ensureDefault(S.emptyState(), catalog);
  assert.ok(S.saveState(state, storage));
  assert.equal(S.loadState(storage).current, "default");
  assert.equal(S.loadState({ getItem: () => { throw new Error("blocked"); } }).current, "");
});

test("include list parse/format", () => {
  const p = profileWith(["5_process_ended/include_security_process_termination.xml", "1_process_creation/include_clear_windows_event_logs.xml"]);
  const text = formatList(p);
  assert.deepEqual(parseList(text, catalog), [...p.modules].sort());
  assert.deepEqual(parseList("# c\n5_process_ended\n", catalog), catalog.moduleRels("5_process_ended"));
});

test("attack matrix and tagging", () => {
  const m = buildMatrix({ techniques: [
    { id: "T1059", name: "CSI", tactics: ["execution"], modules: ["a"], count: 2 },
    { id: "T1059.001", name: "CSI: PowerShell", tactics: ["execution"], modules: ["b"], count: 5 },
    { id: "T1547.001", name: "Boot: Run Keys", tactics: ["persistence", "privilege-escalation"], modules: ["c"], count: 1 },
    { id: "T9999", name: "?", tactics: [], modules: ["x"], count: 1 }], tactics: { execution: 7 }, include: 9, exclude: 0, events: [] });
  assert.deepEqual(m.columns.map(c => c.tactic), ["execution", "persistence", "privilege-escalation", "unmapped"]);
  assert.equal(m.columns[0].techniques[0].total, 7);
  assert.equal(m.columns[2].techniques[0].name, "Boot");
  assert.equal(m.technique_total, 4);
  const t = ruleTagging(catalog, ["1_process_creation/include_clear_windows_event_logs.xml"]);
  assert.equal(t.pct, 100); assert.equal(t.tagged, 3);
});
