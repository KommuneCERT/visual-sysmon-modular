// Browser end-to-end test. Needs a running static server and Playwright:
//   python3 -m http.server -d site 8080 &
//   docker run --rm --network host -v "$PWD:/w" -w /w mcr.microsoft.com/playwright:v1.47.0-jammy \
//     sh -c "npm i --no-save playwright@1.47.0 >/dev/null && node tests/e2e/e2e.mjs"
// BASE=https://kommunecert.github.io/visual-sysmon-modular runs it against the live site.
import { chromium } from "playwright";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const base = (process.env.BASE || "http://localhost:8080").replace(/\/$/, "");
const shots = process.env.SHOTS || "";
const browser = await chromium.launch();
const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1500, height: 1000 } });
const page = await ctx.newPage();
const errors = [];
page.on("console", m => { if (m.type() === "error" || m.type() === "warning") errors.push(`[${m.type()}] ${m.text()}`); });
page.on("pageerror", e => errors.push(`[pageerror] ${e.message}`));
const shot = async name => { if (shots) await page.screenshot({ path: `${shots}/${name}.png` }); };
const step = (name, ok, extra = "") => { console.log(`${ok ? "✓" : "✗"} ${name}${extra ? " – " + extra : ""}`); assert.ok(ok, name); };
const store = fn => page.evaluate(fn);

// ── landing ──
await page.goto(base + "/#/", { waitUntil: "networkidle" });
await page.waitForSelector("#q", { timeout: 15000 });
step("landing shows only the search box", (await page.locator(".vsm-search--hero").count()) === 1 && (await page.locator(".vsm-hit").count()) === 0 && (await page.locator(".vsm-top").isVisible()) && (await page.locator(".vsm-top-title").innerText()) === "SEARCH" && (await page.locator(".vsm-burger").isVisible()));
step("standard configuration = Balanced", (await store(() => Alpine.store("app").profile.modules.length)) === 433);
await page.click(".vsm-burger"); await page.waitForTimeout(200);
step("menu", (await page.locator(".vsm-menu-list").innerText()).includes("Download sysmonconfig.xml") && (await page.locator(".vsm-menu-list .dropdown-header").first().innerText()) === "Standard configuration · 433 modules");
await page.keyboard.press("Escape"); await page.waitForTimeout(200);
step("footer is attribution", (await page.locator(".vsm-footer").innerText()).includes("Built on sysmon-modular"));
await shot("landing");

// ── search + toggles ──
await page.fill("#q", "lsass"); await page.waitForTimeout(600);
step("hits with sentences", (await page.locator(".vsm-hit").count()) > 5 && (await page.locator(".vsm-hit .vsm-sentence").allInnerTexts()).some(t => t.startsWith("Log ProcessAccess when")));
step("hero collapses", (await page.locator(".vsm-search--hero").count()) === 0);
const firstSwitch = page.locator(".vsm-hit-module .vsm-switch").first();
await firstSwitch.uncheck(); await page.waitForTimeout(300);
step("toggle off → 'off' tag + status", (await page.locator(".vsm-hit-module").first().innerText()).includes("off") && (await store(() => Alpine.store("app").statusLine)) === "432 modules · 1 change from standard");
await page.locator(".vsm-hit-module .vsm-switch").first().check(); await page.waitForTimeout(300);
step("toggle on again", (await store(() => Alpine.store("app").statusLine)) === "Standard configuration · 433 modules");
await shot("results");

await page.fill("#q", "lsass_noise"); await page.waitForTimeout(500);
step("module-level hit", (await page.locator(".vsm-hit-ctx").first().innerText()).includes("whole module"));

await page.click("label[for='scope-all']");
await page.fill("#q", "onmatch:exclude event:22 -google"); await page.waitForTimeout(500);
const modulesHit = parseInt((await page.locator(".kc-tag:has-text(' modules'):not(:has-text('hits'))").innerText()), 10);
const before = await store(() => Alpine.store("app").selected.size);
await page.click("button:has-text('Switch off')"); await page.waitForTimeout(300);
step("bulk switch off from search", (await store(() => Alpine.store("app").selected.size)) === before - modulesHit, `${modulesHit} modules`);
await page.click("button:has-text('Switch on all hits')"); await page.waitForTimeout(300);
step("bulk switch on restores", (await store(() => Alpine.store("app").selected.size)) === before);
step("single-category → new module link", (await page.locator("a:has-text('+ New module in 22_dns_query')").count()) === 1);

// ── keyboard ──
await page.keyboard.press("Escape"); await page.keyboard.press("c"); await page.waitForTimeout(300);
step("shortcut c → coverage", (await store(() => location.hash)) === "#/coverage" && (await page.locator(".vsm-top").isVisible()));
await page.keyboard.press("/"); await page.waitForTimeout(500);
step("shortcut / → back to search with query", (await store(() => location.hash)).startsWith("#/?q=") && (await store(() => document.activeElement?.id)) === "q");

// ── editor ──
await page.goto(base + "/#/m/1_process_creation/include_clear_windows_event_logs.xml/edit"); await page.waitForTimeout(500);
step("editor renders fields", (await page.locator(".vsm-cond select").first().inputValue()) === "OriginalFileName");
step("editor has in-config switch + title", (await page.locator(".vsm-top-title").innerText()) === "RULE EDITOR" && (await page.locator("label:has-text('in config') input").isChecked()));
await page.fill(".vsm-cond input.font-monospace >> nth=0", "changed.exe"); await page.waitForTimeout(100);
step("explain updates live", (await page.locator(".vsm-rule .vsm-sentence").first().innerText()).includes("changed.exe"));
const nameInput = page.locator(".vsm-rule .vsm-pick input").first();
await nameInput.fill("T1003.00");
await page.waitForSelector(".vsm-pick-list:visible .vsm-pick-item", { timeout: 5000 });
await nameInput.press("ArrowDown"); await nameInput.press("Enter"); await page.waitForTimeout(100);
step("technique picked", /^technique_id=T1003\.00\d,technique_name=/.test(await nameInput.inputValue()));
await page.click("button:text-is('Save') >> nth=0");
await page.waitForFunction(() => document.body.innerText.includes("Saved to overlay"), null, { timeout: 60000 });
step("editor save validated by engine", (await page.locator("h1 .kc-tag").innerText()) === "edited" && (await store(() => Alpine.store("app").changeCount)) === 1);
await shot("editor");

// ── raw ──
await page.goto(base + "/#/m/1_process_creation/include_clear_windows_event_logs.xml/raw"); await page.waitForTimeout(400);
const xml = await page.inputValue("textarea.vsm-xml-editor");
await page.fill("textarea.vsm-xml-editor", xml.replace(/<CommandLine /g, "<Bogus ").replace(/<\/CommandLine>/g, "</Bogus>"));
await page.click("button:text-is('Save') >> nth=0");
await page.waitForFunction(() => document.body.innerText.includes("Not saved"), null, { timeout: 60000 });
step("raw save blocked on SYS202", (await page.locator(".vsm-findings").innerText()).includes("SYS202"));

// ── download modal ──
await page.goto(base + "/#/"); await page.waitForSelector("#q");
await page.keyboard.press("Escape"); await page.keyboard.press("d");
await page.waitForSelector("#dl.show", { timeout: 120000 }); await page.waitForTimeout(400);
step("download modal", (await page.locator("#dl .kc-section-title").innerText()).includes("433 modules · Sysmon 15.20 (schema 4.91)"));
step("checklist in modal", (await page.locator("#dl .vsm-checklist .kc-callout").count()) >= 1);
await shot("download");
const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#dl button:has-text('Download')")]);
const file = readFileSync(await dl.path(), "utf8");
step("sysmonconfig.xml downloaded", dl.suggestedFilename() === "sysmonconfig.xml" && file.startsWith('<Sysmon schemaversion="4.91">') && file.includes("changed.exe"));
await page.waitForTimeout(400);

// ── footer target ──
await page.click(".vsm-burger"); await page.selectOption(".vsm-menu-target select", "14"); await page.keyboard.press("Escape"); await page.waitForTimeout(200);
await page.keyboard.press("d");
await page.waitForSelector("#dl.show", { timeout: 120000 }); await page.waitForTimeout(300);
step("target change → schema 4.82", (await page.locator("#dl .kc-section-title").innerText()).includes("Sysmon 14 (schema 4.82)"));
await page.click("#dl button:has-text('Close')"); await page.waitForTimeout(400);
await page.click(".vsm-burger"); await page.selectOption(".vsm-menu-target select", "15.20"); await page.keyboard.press("Escape"); await page.waitForTimeout(200);

// ── coverage + help ──
await page.click(".vsm-burger"); await page.click(".vsm-menu-list a:has-text('ATT&CK coverage')"); await page.waitForSelector(".vsm-tactic", { timeout: 60000 });
step("coverage from menu", (await page.locator(".vsm-tactic").count()) >= 10);
await page.click(".vsm-burger"); await page.click(".vsm-menu-list a:has-text('Help')"); await page.waitForSelector("#help-root section");
step("help event table", (await page.locator("#event-table tbody tr").count()) >= 20 && (await page.locator("#cost-table tbody tr").count()) >= 20);
await page.click("#event-table a:has-text('search') >> nth=0"); await page.waitForTimeout(600);
step("event table → search cat:", (await store(() => location.hash)).includes("q=event%3A1") || (await store(() => location.hash)).includes("q=event:1"));
await page.goto(base + "/#/help"); await page.waitForSelector("#help-root section");
await page.click(".vsm-toc a:has-text('Condition operators')");
const scrolled = await page.waitForFunction(() => location.hash === "#/help/conditions" && Math.abs(document.getElementById("conditions").getBoundingClientRect().top) < 120, null, { timeout: 5000 }).then(() => true).catch(() => false);
step("help section link", scrolled);

// ── new module via Save/Load menu ──
await page.goto(base + "/#/new?cat=22_dns_query"); await page.waitForSelector("input[placeholder*='EDR']");
await page.fill("input[placeholder*='EDR']", "Our DNS test");
await page.selectOption("select[x-model=\"kind\"]", "exclude");
await page.click("text=Create and edit");
await page.waitForFunction(() => location.hash.includes("/edit"));
step("custom module created", (await store(() => location.hash)) === "#/m/22_dns_query/exclude_our_dns_test.xml/edit" && (await page.locator("h1 .kc-tag").innerText()) === "custom");

// ── your changes ──
await page.click(".vsm-burger"); await page.click(".vsm-menu-list a:has-text('Your changes')"); await page.waitForSelector("#changes.show"); await page.waitForTimeout(300);
const changesText = await page.locator("#changes .modal-body").innerText();
step("changes modal lists edits and custom modules", (await page.locator("#changes .kc-section-title").innerText()).startsWith("2 changes") && changesText.includes("Edited modules") && changesText.includes("Custom modules") && changesText.includes("exclude_our_dns_test.xml"));
step("status counts changes", (await store(() => Alpine.store("app").statusLine)).includes("2 changes from standard"));
await page.click("#changes button:has-text('Close')"); await page.waitForTimeout(400);

// ── export → clear → import; reset ──
const [exp] = await Promise.all([page.waitForEvent("download"), store(() => Alpine.store("app").exportAll())]);
const exportPath = await exp.path();
await store(() => localStorage.clear());
await page.goto(base + "/#/"); await page.reload(); await page.waitForSelector("#q");
step("fresh state after clear", (await store(() => Alpine.store("app").overlayRels.length)) === 0);
await store(() => { Alpine.store("app").importMode = "replace"; });
await page.setInputFiles("input[type=file][accept='.json']", exportPath); await page.waitForTimeout(600);
step("import restores edits", (await store(() => Alpine.store("app").overlayRels.length)) === 2);
page.once("dialog", d => d.accept());
await store(() => Alpine.store("app").resetToStandard()); await page.waitForTimeout(300);
step("reset to standard", (await store(() => Alpine.store("app").overlayRels.length)) === 0 && (await store(() => Alpine.store("app").profile.modules.length)) === 433);

console.log(`console errors: ${errors.length}`); errors.forEach(e => console.log("  ", e.slice(0, 200)));
assert.equal(errors.length, 0);
await browser.close();
