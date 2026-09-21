// Browser end-to-end test. Needs a running static server and Playwright:
//   python3 -m http.server -d site 8080 &
//   docker run --rm --network host -v "$PWD:/w" -w /w mcr.microsoft.com/playwright:v1.47.0-jammy \
//     sh -c "npm i --no-save playwright@1.47.0 >/dev/null && node tests/e2e/e2e.mjs"
// BASE=https://kommunecert.github.io/visual-sysmon-modular runs it against the live site.
import { chromium } from "playwright";
import assert from "node:assert/strict";

const base = (process.env.BASE || "http://localhost:8080").replace(/\/$/, "");
const shots = process.env.SHOTS || "";
const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1500, height: 1000 } });
const page = await ctx.newPage();
const errors = [];
page.on("console", m => { if (m.type() === "error" || m.type() === "warning") errors.push(`[${m.type()}] ${m.text()}`); });
page.on("pageerror", e => errors.push(`[pageerror] ${e.message}`));
const shot = async name => { if (shots) await page.screenshot({ path: `${shots}/${name}.png` }); };
const hashIs = re => page.waitForFunction(r => new RegExp(r).test(location.hash), re.source, { timeout: 120000 });
const step = (name, ok, extra = "") => { console.log(`${ok ? "✓" : "✗"} ${name}${extra ? " – " + extra : ""}`); assert.ok(ok, name); };

// ── wizard on first visit ──
await page.goto(base + "/#/", { waitUntil: "networkidle" });
await page.waitForSelector("#wizard.show", { timeout: 15000 });
const presetCards = await page.locator("#wizard .vsm-env").count();
step("wizard auto-opens with upstream presets", presetCards === 4, `${presetCards} cards`);
await shot("wizard");
await page.click("#wizard .vsm-env:has(.vsm-env-title:text-is('Balanced'))");
await page.click("#wizard button:has-text('Sysmon 14.1')");
await page.click("#wizard button:has-text('Next')");
await page.fill("#wizard input", "ws-pilot");
await page.click("#wizard button:has-text('Create profile')");
await page.waitForFunction(() => location.hash === "#/profile" && !document.querySelector("#wizard.show"));
await page.waitForTimeout(300);
const prof = await page.evaluate(() => { const p = Alpine.store("app").profile; return { slug: p.slug, n: p.modules.length, v: p.sysmon_version, preset: p.preset, unsupported: p.unsupported }; });
step("profile created from Balanced preset", prof.preset === "balanced" && prof.n === 433 && prof.v === "14.1" && prof.unsupported === "exclude", JSON.stringify(prof));
step("checklist says not built yet", (await page.locator(".vsm-checklist").first().innerText()).includes("Not built yet"));

// ── search ──
await page.goto(base + "/#/?q=lsass"); await page.waitForTimeout(500);
const sentences = await page.locator(".vsm-hit .vsm-sentence").allInnerTexts();
step("search hits with sentences", (await page.locator(".vsm-hit").count()) > 5 && sentences.some(t => t.startsWith("Log ProcessAccess when")));
await page.fill("#q", "lsass_noise"); await page.waitForTimeout(500);
step("module-level hit", (await page.locator(".vsm-hit-ctx").first().innerText()).includes("whole module"));

// ── search syntax + bulk actions ──
await page.click("label[for='scope-all']");
await page.fill("#q", "kind:exclude cat:22 -google"); await page.waitForTimeout(500);
const hitMods = await page.evaluate(() => [...new Set([...document.querySelectorAll(".vsm-hit-path code")].map(e => e.textContent))]);
step("query syntax filters", hitMods.length > 3 && hitMods.every(r => r.startsWith("22_dns_query/exclude_") && !/google/.test(r)), `${hitMods.length} modules`);
const modulesHit = parseInt((await page.locator(".kc-tag:has-text(' modules'):not(:has-text('hits'))").innerText()), 10);
const beforeBulk = await page.evaluate(() => Alpine.store("app").selected.size);
await page.click("button:has-text('Deselect')"); await page.waitForTimeout(300);
const afterBulk = await page.evaluate(() => Alpine.store("app").selected.size);
step("bulk deselect from search", afterBulk === beforeBulk - modulesHit, `${beforeBulk} → ${afterBulk} (${modulesHit} modules hit)`);
await page.click("button:has-text('Select all hit modules')"); await page.waitForTimeout(300);
step("bulk select restores", (await page.evaluate(() => Alpine.store("app").selected.size)) === beforeBulk);

// ── keyboard shortcuts ──
await page.keyboard.press("Escape"); await page.keyboard.press("p"); await page.waitForTimeout(200);
step("shortcut p → profile", (await page.evaluate(() => location.hash)) === "#/profile");
await page.keyboard.press("/"); await page.waitForTimeout(400);
step("shortcut / → search focused", (await page.evaluate(() => location.hash)) === "#/" && (await page.evaluate(() => document.activeElement?.id)) === "q");

// ── category: toggles, volume badge, sentences ──
await page.goto(base + "/#/c/7_image_load"); await page.waitForTimeout(400);
step("high volume badge + popover", (await page.locator(".kc-tag-red:has-text('high volume')").count()) === 1);
await page.hover(".vsm-vol-tag >> nth=0"); await page.waitForTimeout(400);
step("sidebar volume popover", (await page.locator(".popover").innerText()).includes("High-volume"));
step("card sentence", (await page.locator(".vsm-card .vsm-sentence").first().innerText()).match(/^(Log|Ignore) ImageLoad when /) !== null);
const before = await page.evaluate(() => Alpine.store("app").selected.size);
await page.locator(".vsm-card .vsm-switch").first().uncheck(); await page.waitForTimeout(200);
step("toggle off persists", (await page.evaluate(() => Alpine.store("app").selected.size)) === before - 1);
await page.locator(".vsm-card .vsm-switch").first().check();
await page.click("button.dropdown-toggle:has-text('Select')"); await page.click("button.dropdown-item:has-text('Deselect all in this category')"); await page.waitForTimeout(200);
step("category Select ▾ deselects", (await page.evaluate(() => Alpine.store("app").sidebar.find(r => r.cat.dirname === "7_image_load").selected)) === 0);
await page.click("button.dropdown-toggle:has-text('Select')"); await page.click("button.dropdown-item:has-text('All modules in this category')"); await page.waitForTimeout(200);

// ── editor: explain + save via WASM ──
await page.goto(base + "/#/m/1_process_creation/include_clear_windows_event_logs.xml/edit"); await page.waitForTimeout(500);
step("editor renders fields", (await page.locator(".vsm-cond select").first().inputValue()) === "OriginalFileName");
await page.fill(".vsm-cond input.font-monospace >> nth=0", "changed.exe"); await page.waitForTimeout(100);
step("explain updates live", (await page.locator(".vsm-rule .vsm-sentence").first().innerText()).includes("changed.exe"));
step("ATT&CK status on existing rule", (await page.locator(".vsm-rule .vsm-pick-status").first().innerText()).includes("ATT&CK"));
const nameInput = page.locator(".vsm-rule .vsm-pick input").first();
await nameInput.fill("T1003.00"); await page.waitForTimeout(200);
step("technique suggestions", (await page.locator(".vsm-pick-list:visible .vsm-pick-item").count()) >= 5);
await nameInput.press("ArrowDown"); await nameInput.press("Enter"); await page.waitForTimeout(100);
step("technique picked", /^technique_id=T1003\.00\d,technique_name=/.test(await nameInput.inputValue()) && (await page.locator(".vsm-rule .vsm-pick-status").first().innerText()).includes("✓"), await nameInput.inputValue());
await page.click("button:text-is('Save') >> nth=0");
await page.waitForFunction(() => document.body.innerText.includes("Saved to overlay"), null, { timeout: 60000 });
step("editor save validated by engine", true);
await page.goto(base + "/#/c/1_process_creation"); await page.waitForTimeout(400);
step("edited badge", (await page.locator(".vsm-card:has-text('include_clear_windows_event_logs.xml') .kc-tag-green").count()) === 1);

// ── raw editor: invalid field blocked ──
await page.goto(base + "/#/m/1_process_creation/include_clear_windows_event_logs.xml/raw"); await page.waitForTimeout(400);
const xml = await page.inputValue("textarea.vsm-xml-editor");
await page.fill("textarea.vsm-xml-editor", xml.replace(/<CommandLine /g, "<Bogus ").replace(/<\/CommandLine>/g, "</Bogus>"));
await page.click("button:text-is('Save') >> nth=0");
await page.waitForFunction(() => document.body.innerText.includes("Not saved"), null, { timeout: 60000 });
step("raw save blocked on SYS202", (await page.locator(".vsm-findings").innerText()).includes("SYS202"));

// ── build ──
await page.click("nav button:has-text('▶ Build')");
await hashIs(/^#\/build\//); await page.waitForTimeout(600);
step("build ok, deploy tab default", (await page.locator("h1 .kc-severity").innerText()) === "OK" && (await page.locator(".nav-tabs .nav-link.active").innerText()) === "Deploy");
step("five tabs, no log", (await page.locator(".nav-tabs .nav-link").count()) === 5);
step("deploy commands", (await page.locator(".vsm-cmd").count()) === 4);
await page.click(".nav-tabs >> text=Coverage"); await page.waitForTimeout(300);
step("matrix in build", (await page.locator(".vsm-tactic").count()) >= 10);
await page.click(".nav-tabs >> text=XML"); await page.waitForTimeout(800);
step("xml view highlighted", (await page.locator(".vsm-xml-view .x-t").count()) > 100);
await shot("build");
const firstBuild = await page.evaluate(() => location.hash);
await page.click("nav button:has-text('▶ Build')");
await page.waitForFunction(b => location.hash.startsWith("#/build/") && location.hash !== b, firstBuild); await page.waitForTimeout(500);
await page.click(".nav-tabs >> text=Diff"); await page.waitForTimeout(300);
const diffText = await page.locator("[x-show=\"tab === 'diff'\"]").innerText();
const diffMeta = await page.evaluate(() => { const b = Alpine.store("app").build(location.hash.slice(8)); return { has: !!b.diff, before: b.diff_before, n: Alpine.store("app").buildsFor(b.profile).length }; });
step("diff against previous build", diffText.includes("No semantic changes"), JSON.stringify(diffMeta) + " " + diffText.slice(0, 80).replace(/\n/g, " "));

// ── coverage page ──
await page.goto(base + "/#/coverage"); await page.waitForSelector(".vsm-tactic", { timeout: 60000 });
await page.locator(".vsm-tech").first().click(); await page.waitForTimeout(200);
step("coverage matrix + drill-down", (await page.locator(".vsm-tech-detail").isVisible()));

// ── help navigation ──
await page.goto(base + "/#/help"); await page.waitForSelector("#help-root section");
await page.click(".vsm-toc a:has-text('Condition operators')");
const scrolled = await page.waitForFunction(() => location.hash === "#/help/conditions" && Math.abs(document.getElementById("conditions").getBoundingClientRect().top) < 120, null, { timeout: 5000 }).then(() => true).catch(() => false);
step("help section link", scrolled, await page.evaluate(() => location.hash + " top=" + Math.round(document.getElementById("conditions").getBoundingClientRect().top)));

// ── export / import / persistence ──
const [dl] = await Promise.all([page.waitForEvent("download"), page.evaluate(() => Alpine.store("app").exportAll())]);
const exportPath = await dl.path();
await page.evaluate(() => localStorage.clear());
await page.reload(); await page.waitForSelector(".vsm-catlist a");
await page.click("#wizard button:has-text('Skip')").catch(() => {});
await page.evaluate(() => { Alpine.store("app").importMode = "replace"; });
await page.setInputFiles("input[type=file][accept='.json']", exportPath); await page.waitForTimeout(600);
step("export → clear → import restores overlay + profile", (await page.evaluate(() => Alpine.store("app").overlayRels.length)) === 1 && (await page.evaluate(() => Alpine.store("app").profiles.map(p => p.slug))).includes("ws-pilot"));

console.log(`console errors: ${errors.length}`); errors.forEach(e => console.log("  ", e.slice(0, 200)));
assert.equal(errors.length, 0);
await browser.close();
