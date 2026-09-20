// Volume guidance per event category and a plain-language "before you deploy" checklist.
import { kindOf } from "./catalog.js";
import { ruleTagging } from "./attack.js";

export const VOLUME = {
  "7_image_load": { level: "high", why: "Every DLL load by every process. Only viable with tight include rules; a broad selection can produce thousands of events per minute." },
  "10_process_access": { level: "high", why: "Every process opening another process (diagnostic tools, AV, browsers do this constantly). Keep the includes focused on lsass.exe & co and keep the exclusions." },
  "12_13_14_registry_event": { level: "high", why: "Registry writes are extremely frequent. Include modules target autostart keys; do not widen them without exclusions." },
  "11_file_create": { level: "medium", why: "File creation in monitored folders. Fine with the shipped exclusions; browsers and updaters are noisy without them." },
  "3_network_connection_initiated": { level: "medium", why: "One event per outbound connection. Manageable with exclusions; watch servers with many clients." },
  "22_dns_query": { level: "medium", why: "One event per DNS lookup. Cached lookups are not repeated, but browsers still generate many." },
  "1_process_creation": { level: "medium", why: "The most valuable event. Volume is usually fine; scripts and build tools that spawn many processes are the exception." },
  "23_file_delete": { level: "medium", why: "Deleted files are also copied into C:\\Sysmon (ArchiveDirectory). Disk usage grows on busy hosts – prefer event 26 unless you need the file contents." },
  "26_file_delete_detected": { level: "medium", why: "Logs deletions without archiving the file. Cheaper than event 23, still frequent in temp folders." },
};
export const volumeOf = cat => VOLUME[cat] || { level: "low", why: "Low-volume event type on typical hosts." };

const item = (level, title, detail, href = "") => ({ level, title, detail, href });

/** profile: {modules, sysmon_version, unsupported}; lastBuild: build meta or null. */
export function checklist(catalog, profile, lastBuild) {
  const out = [];
  const rels = profile.modules;
  if (!rels.length) return [item("error", "No modules selected", "Pick a preset on the Profile page or switch modules on in the categories.", "#/profile")];
  const includes = rels.filter(r => kindOf(r) === "include");
  const excludes = rels.filter(r => kindOf(r) === "exclude");
  const allExcludes = catalog.allRels().filter(r => kindOf(r) === "exclude");

  if (!includes.length) out.push(item("warn", "Only exclusion modules are selected", "Every event type with an exclude filter is logged in full except the known noise – expect very high volume. Fine for research, not for a fleet.", "#/profile"));
  if (allExcludes.length && !excludes.length) out.push(item("warn", "All noise exclusions are switched off", "The shipped exclude modules remove known-good noise (updaters, AV, browsers). Without them, volume on busy hosts is much higher.", "#/profile"));

  for (const cat of catalog.categoryDirs()) {
    const v = VOLUME[cat];
    if (!v || v.level !== "high") continue;
    const inCat = rels.filter(r => r.startsWith(cat + "/"));
    if (!inCat.length) continue;
    const catIncl = inCat.filter(r => kindOf(r) === "include"), catExcl = inCat.filter(r => kindOf(r) === "exclude");
    const availExcl = catalog.moduleRels(cat).filter(r => kindOf(r) === "exclude");
    if (!catIncl.length && catExcl.length) out.push(item("warn", `${cat}: exclude-only – everything is logged`, `Without an include filter this high-volume event type is collected in full except the excluded noise. ${v.why}`, `#/c/${cat}`));
    else if (catIncl.length && availExcl.length && !catExcl.length) out.push(item("warn", `${cat}: no noise exclusions selected`, `High-volume event type with all ${availExcl.length} exclusion modules off. ${v.why}`, `#/c/${cat}`));
  }
  if (rels.some(r => r.startsWith("23_file_delete/"))) out.push(item("info", "FileDelete archiving (event 23) is on", "Deleted files are copied to the Sysmon archive directory on each host. Make sure disk growth is acceptable, or use event 26 (FileDeleteDetected) instead.", "#/c/23_file_delete"));

  if (Number(profile.sysmon_version) < 15 && profile.unsupported !== "exclude") out.push(item("warn", `Target Sysmon ${profile.sysmon_version} with unsupported items kept`, "Events or fields newer than the target are only warned about, so the file may fail to load on the older binary. Set 'unsupported' to remove them, or target the version you actually run.", "#/profile"));

  const custom = rels.filter(r => catalog.sourceOf(r) === "custom");
  if (custom.length) {
    const t = ruleTagging(catalog, custom);
    if (t.untagged) out.push(item("info", `${t.untagged} include rules in your custom modules have no ATT&CK tag`, "They still log events but do not show in coverage. Add technique_id=…,technique_name=… to the Rule or RuleGroup name.", "#/coverage"));
  }

  if (!lastBuild) out.push(item("info", "Not built yet", "Press Build to merge and validate the selection – the result page shows findings, coverage and the deploy commands.", ""));
  else {
    if (!lastBuild.ok || lastBuild.summary?.error) out.push(item("error", "The last build has errors", "Errors mean the merged file is invalid or contains unknown fields. Open the build, fix the modules it names and build again.", `#/build/${lastBuild.id}`));
    const anl006 = (lastBuild.findings || []).filter(f => f.code === "ANL006").length;
    if (anl006) out.push(item("info", `${anl006} exclusions match by bare image name`, "An exclude like Image=outlook.exe also silences a lookalike C:\\Temp\\outlook.exe. Prefer full paths for exclusions where you can (analyzer ANL006).", `#/build/${lastBuild.id}`));
    const w = lastBuild.summary?.warning || 0;
    if (w) out.push(item("info", `${w} warnings in the last build`, "Usually events/fields the target Sysmon version does not support. Review them on the build page.", `#/build/${lastBuild.id}`));
    if (profile.updated && lastBuild.created && profile.updated > lastBuild.created) out.push(item("warn", "Profile changed after the last build", "The downloadable XML is older than your current selection or edits. Build again before deploying.", ""));
  }
  return out;
}
