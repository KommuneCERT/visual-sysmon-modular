// Volume guidance per event category and a plain-language "before you deploy" checklist.
import { kindOf } from "./catalog.js";
import { ruleTagging } from "./attack.js";

// Inherent cost of enabling an event type – independent of which modules are selected.
// Dimensions: volume (events/s), cpu (per-event work on the host), disk (archive / IO), privacy.
export const COST = {
  "1_process_creation": { volume: "medium", cpu: "medium", disk: "low",
    why: "One event per process start; every image is hashed with all configured algorithms (MD5, SHA1, SHA256, IMPHASH). Usually fine; scripts and build tools that spawn thousands of processes are the exception." },
  "2_file_create_time": { volume: "low", cpu: "low", disk: "low", why: "Only fires on explicit creation-time changes. Cheap." },
  "3_network_connection_initiated": { volume: "high", cpu: "low", disk: "low",
    why: "One event per outbound TCP/UDP connection. Cheap per event but many on servers and browsers. Reverse DNS (DnsLookup) is off in the template – turning it on adds a lookup per event." },
  "5_process_ended": { volume: "medium", cpu: "low", disk: "low", why: "Mirrors process creation in count; trivial per event." },
  "6_driver_loaded_into_kernel": { volume: "low", cpu: "low", disk: "low", why: "Rare events; each driver is hashed and signature-checked, but there are few of them." },
  "7_image_load": { volume: "high", cpu: "high", disk: "low",
    why: "Every DLL load by every process, and each one is hashed and signature-verified – the most CPU-expensive event type. Only viable with tight include rules; a broad selection can cost 5–15 % CPU and thousands of events per minute." },
  "8_create_remote_thread": { volume: "low", cpu: "low", disk: "low", why: "Rare in normal operation; cheap." },
  "9_raw_access_read": { volume: "high", cpu: "high", disk: "low",
    why: "Sector-level reads via \\\\.\\ device paths. Backup agents, AV scans, defrag and disk tools issue thousands of reads per second, each passing the Sysmon driver – CPU spikes and log floods during backups. Upstream ships it OFF (an empty include filter); any include rule activates it. Typically only enabled on domain controllers with exclusions for backup/AV." },
  "10_process_access": { volume: "high", cpu: "high", disk: "low",
    why: "Every process opening another process – diagnostic tools, AV and browsers do this constantly – and Sysmon builds a call-stack trace (CallTrace) for each event. Keep the includes focused on lsass.exe & co and keep the exclusions." },
  "11_file_create": { volume: "high", cpu: "low", disk: "low",
    why: "One event per file created or overwritten in monitored locations; no hashing. Browsers, updaters and temp folders are noisy without the shipped exclusions." },
  "12_13_14_registry_event": { volume: "high", cpu: "low", disk: "low",
    why: "Registry writes are extremely frequent; cheap per event but the volume hits the event log and forwarders. Include modules target autostart keys – do not widen them without exclusions." },
  "15_file_create_stream_hash": { volume: "medium", cpu: "medium", disk: "low",
    why: "Fires on alternate data streams (browser downloads get a Zone.Identifier stream) and hashes the file contents. Moderate; large downloads cost a hash each." },
  "17_18_pipe_event": { volume: "medium", cpu: "low", disk: "low", why: "Named-pipe creation/connection. Chatty on servers with RPC-heavy software, cheap per event." },
  "19_20_21_wmi_event": { volume: "low", cpu: "low", disk: "low", why: "WMI subscription changes are rare; cheap." },
  "22_dns_query": { volume: "high", cpu: "low", disk: "low",
    why: "One event per DNS lookup (cached lookups are not repeated). Browsers and telemetry generate many; cheap per event." },
  "23_file_delete": { volume: "high", cpu: "medium", disk: "high",
    why: "Every matching deleted file is hashed and COPIED into the Sysmon archive directory (C:\\Sysmon by default, system ACL, no automatic rotation) before removal. Disk grows until you clean up; busy file/database/build servers can fill a volume. Prefer event 26 unless you need the file contents." },
  "24_clipboard_change": { volume: "low", cpu: "low", disk: "medium", privacy: "high",
    why: "Every clipboard change is logged AND the clipboard text is written to the archive directory. Cheap, but it captures passwords and personal data users copy – a GDPR/privacy decision, not a performance one." },
  "25_process_tampering": { volume: "low", cpu: "low", disk: "low", why: "Hollowing/herpaderping detection; rare events, cheap." },
  "26_file_delete_detected": { volume: "high", cpu: "medium", disk: "low",
    why: "Logs deletions and hashes the deleted file, without archiving it. Frequent in temp folders; the cheaper alternative to event 23." },
  "29_file_executable_detected": { volume: "medium", cpu: "medium", disk: "low",
    why: "Fires when a new PE file is written; the file is hashed. Moderate on build servers and during software installs." },
};
const DEFAULT_COST = { volume: "low", cpu: "low", disk: "low", why: "Low-cost event type on typical hosts." };
export const costOf = cat => COST[cat] || DEFAULT_COST;
// Tags worth showing next to the category name (highest-impact dimensions only).
export function costTags(cat, { max = 4 } = {}) {
  const c = costOf(cat), tags = [];
  if (c.volume === "high") tags.push({ key: "volume", label: "high", cls: "vsm-vol-tag", prio: 3 });
  if (c.cpu === "high") tags.push({ key: "cpu", label: "cpu", cls: "vsm-vol-tag vsm-vol-tag--cpu", prio: 2 });
  if (c.disk === "high") tags.push({ key: "disk", label: "disk", cls: "vsm-vol-tag vsm-vol-tag--disk", prio: 1 });
  if (c.privacy === "high") tags.push({ key: "privacy", label: "privacy", cls: "vsm-vol-tag vsm-vol-tag--privacy", prio: 0 });
  return tags.sort((a, b) => a.prio - b.prio).slice(0, max);
}
// Backwards-compatible view used by the checklist.
export const VOLUME = Object.fromEntries(Object.entries(COST).map(([k, c]) => [k, { level: c.volume, disk: c.disk === "high", why: c.why }]));
export const volumeOf = cat => VOLUME[cat] || { level: "low", disk: false, why: DEFAULT_COST.why };

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
  const raw = rels.filter(r => r.startsWith("9_raw_access_read/") && kindOf(r) === "include");
  if (raw.length) {
    let active = false;
    for (const r of raw) { try { const m = catalog.parsed(r); active = active || m.rulegroups.some(rg => rg.events.some(ev => ev.onmatch === "include" && (ev.rules.length || ev.conditions.length))); } catch { /* ignore */ } }
    if (active) out.push(item("warn", "RawAccessRead (event 9) is active", "An include rule with conditions switches on sector-level read monitoring. Backup agents, AV scans and defrag generate thousands of reads per second – expect CPU spikes and log floods during backups. Upstream ships this event off; keep it to domain controllers and add exclusions for your backup/AV software.", "#/c/9_raw_access_read"));
  }
  const fd = rels.filter(r => r.startsWith("23_file_delete/"));
  if (fd.some(r => kindOf(r) === "include")) out.push(item("warn", "FileDelete archiving (event 23) is on – watch disk usage", `Every deleted file that matches the ${fd.filter(r => kindOf(r) === "include").length} selected include module(s) is copied into C:\\Sysmon on each host and never rotated. Busy file, database or build servers can fill a disk. Either keep the includes narrow, add exclusions, plan a cleanup job for the archive directory – or use event 26 (FileDeleteDetected), which logs deletions without keeping the file.`, "#/c/23_file_delete"));

  if (Number(profile.sysmon_version) < 15 && profile.unsupported !== "exclude") out.push(item("warn", `Target Sysmon ${profile.sysmon_version} with unsupported items kept`, "Events or fields newer than the target are only warned about, so the file may fail to load on the older binary. Enable 'Remove events and fields the target version does not support' in the build settings, or target the version you actually run.", "#/profile"));

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
