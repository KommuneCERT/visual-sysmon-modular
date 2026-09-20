import test from "node:test";
import assert from "node:assert/strict";
import { describeCondition, describeRule, describeBare, describeEvent, describeModule } from "../../site/js/describe.js";
import { parseModule } from "../../site/js/model.js";

test("condition wording", () => {
  assert.equal(describeCondition({ field: "Image", condition: "image", value: "powershell.exe" }), "Image is the process `powershell.exe`");
  assert.equal(describeCondition({ field: "CommandLine", condition: "contains any", value: " cl ;clear-log" }), "CommandLine contains any of `cl`, `clear-log`");
  assert.equal(describeCondition({ field: "TargetObject", condition: "begin with", value: "HKLM\\x" }), "TargetObject starts with `HKLM\\x`");
  assert.equal(describeCondition({ field: "X", condition: "", value: "1" }), "X is `1`");
});

test("rules, bare conditions and events", () => {
  const r = { group_relation: "and", conditions: [{ field: "Image", condition: "image", value: "a.exe" }, { field: "CommandLine", condition: "contains", value: "-enc" }] };
  assert.equal(describeRule(r), "Image is the process `a.exe` and CommandLine contains `-enc`");
  assert.equal(describeRule({ ...r, group_relation: "or" }), "Image is the process `a.exe` or CommandLine contains `-enc`");
  assert.equal(describeRule({ group_relation: "and", conditions: [] }), "(no conditions – matches nothing)");
  const bare = [{ field: "Image", condition: "is", value: "a" }, { field: "Image", condition: "is", value: "b" }, { field: "User", condition: "is", value: "u" }];
  assert.equal(describeBare(bare, ""), "(Image is `a` or Image is `b`) and User is `u`");
  assert.equal(describeBare(bare, "or"), "Image is `a` or Image is `b` or User is `u`");
  const ev = { event_type: "ProcessCreate", onmatch: "exclude", conditions: bare.slice(0, 1), rules: [r] };
  assert.deepEqual(describeEvent(ev, "or"), ["Ignore ProcessCreate when Image is `a`", "Ignore ProcessCreate when Image is the process `a.exe` and CommandLine contains `-enc`"]);
  assert.deepEqual(describeEvent({ event_type: "DnsQuery", onmatch: "include", conditions: [], rules: [] }, "or"), ["Log nothing for DnsQuery (empty include filter)"]);
});

test("module summary", () => {
  const m = parseModule(`<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="g" groupRelation="or"><ProcessCreate onmatch="include">
    <Rule name="a" groupRelation="and"><Image condition="image">x.exe</Image></Rule>
    <Rule name="b" groupRelation="and"><Image condition="image">y.exe</Image></Rule>
    <Rule name="c" groupRelation="and"><Image condition="image">z.exe</Image></Rule>
    <Rule name="d" groupRelation="and"><Image condition="image">w.exe</Image></Rule>
  </ProcessCreate></RuleGroup></EventFiltering></Sysmon>`);
  const d = describeModule(m, { max: 3 });
  assert.equal(d.sentences.length, 3); assert.equal(d.more, 1); assert.equal(d.total, 4);
  assert.equal(d.sentences[0], "Log ProcessCreate when Image is the process `x.exe`");
});
