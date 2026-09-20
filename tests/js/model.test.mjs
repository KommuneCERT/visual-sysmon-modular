import test from "node:test";
import assert from "node:assert/strict";
import { parseXml, parseModule, toXml, summarize, emptyModule, isWellFormed, ruleToXml } from "../../site/js/model.js";

const SAMPLE = `<Sysmon schemaversion="4.90">
  <!-- comment -->
  <EventFiltering>
    <RuleGroup name="Mission-important Windows event log clearing" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">bare.exe</Image>
        <Rule name="technique_id=T1685.005,technique_name=Clear Windows Event Logs" groupRelation="and">
          <OriginalFileName condition="is">wevtutil.exe</OriginalFileName>
          <CommandLine condition="contains any"> cl ;clear-log &amp; &lt;x&gt;</CommandLine>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
`;

test("parse and roundtrip", () => {
  const m = parseModule(SAMPLE);
  assert.equal(m.schemaversion, "4.90");
  const ev = m.rulegroups[0].events[0];
  assert.equal(ev.event_type, "ProcessCreate");
  assert.deepEqual(ev.conditions.map(c => c.field), ["Image"]);
  assert.equal(ev.rules[0].conditions[1].value, "cl ;clear-log & <x>");
  const xml = toXml(m);
  assert.ok(xml.includes('condition="contains any"'));
  assert.ok(xml.includes("clear-log &amp; &lt;x&gt;"));
  assert.deepEqual(parseModule(xml), m);
  const s = summarize(m);
  assert.deepEqual(s.techniques, [["T1685.005", "Clear Windows Event Logs"]]);
  assert.equal(s.rule_count, 2);
});

test("parser errors carry line numbers", () => {
  assert.throws(() => parseXml("<Sysmon>\n<broken"), /line 2/);
  assert.throws(() => parseXml("<a></b>"), /does not match/);
  assert.throws(() => parseXml("<a/><b/>"), /multiple document roots/);
  assert.deepEqual(isWellFormed("<a/>"), [true, ""]);
  assert.equal(isWellFormed("")[0], false);
  assert.throws(() => parseModule("<Nope/>"), /root element must be <Sysmon>/);
});

test("empty module and rule serialisation", () => {
  const m = emptyModule("DnsQuery", "exclude", "My group");
  assert.ok(toXml(m).includes('<DnsQuery onmatch="exclude"/>'));
  assert.equal(ruleToXml({ name: "", group_relation: "or", conditions: [] }), '<Rule groupRelation="or"/>');
  assert.ok(ruleToXml({ name: 'a"b', group_relation: "and", conditions: [{ field: "Image", condition: "is", value: "x", name: "" }] }).includes('name="a&quot;b"'));
});
