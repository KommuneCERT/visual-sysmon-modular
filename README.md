# Visual Sysmon Modular

A browser-only GUI for [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular).
Pick modules per Sysmon event, edit rules in a form or as raw XML, validate, merge and download a
`sysmonconfig.xml` – all inside your browser. Upstream's own Go tooling (merge, validate, analyze,
ATT&CK coverage, semantic diff) is compiled to WebAssembly, so the result is exactly what
`sysmon-modular merge` would produce. Nothing is uploaded anywhere.

**Live site:** https://kommunecert.github.io/visual-sysmon-modular/

## What you can do

- **Guided start** – first visit asks what you are configuring (workstations, servers, hosts with
  Defender for Endpoint, research) and which Sysmon version, then creates a profile from one of
  upstream's published presets (Balanced, +FileDelete, MDE augment, Excludes only).
- **Plain-language rules** – every module card, search hit and editor rule is explained as a sentence
  ("Log ProcessCreate when Image is the process `wevtutil.exe` and CommandLine contains …").
- **Before you deploy** – a checklist on the Profile and build pages flags empty/exclude-only selections,
  high-volume event types without their noise exclusions, target-version pitfalls and analyzer hints.
- **Deploy tab** – copyable install/update/verify/rollback commands for each build.
- **Search** the current configuration as you type – hits are the matching `<Rule>`/condition in
  context (module → RuleGroup → event), syntax-highlighted with the match marked.
- **Profiles** – independent module selections with their own target Sysmon version (12–15) and
  build options; one per fleet.
- **Categories** – the same directories as upstream; toggle include (detection) and exclude (noise)
  modules, or select all/includes/excludes per category.
- **Rule editor** – RuleGroup → event → Rule → conditions with field/operator dropdowns from the
  Sysmon schema. Saving validates with upstream's validator.
- **Raw XML** editor with highlighting, validation and "save anyway".
- **Overlay** – upstream modules are never changed; your edits and custom modules shadow them.
  *Reset to upstream* removes your copy.
- **Build** – merge + schema validation + analyzer; findings by severity, ATT&CK matrix, semantic diff
  against the previous build, log and highlighted XML. Last 10 builds per profile are kept.
- **Coverage** – live ATT&CK tactic × technique matrix for the selected modules, tagged-vs-untagged
  rule stats, Navigator layer export.
- **Import/export** of upstream-style include/exclude lists, and **Save / Load** of everything
  (profiles + overlay) as one JSON file.
- **Help** page explaining the workflow and how Sysmon include/exclude filtering works.

## Where your data lives

In your browser only: profiles and edited modules in `localStorage`, build outputs in IndexedDB.
Clearing site data or switching devices starts from scratch – use **Save / Load** to export a JSON
file and keep it in your own repo. Exports reference upstream modules by path, so they stay valid
across upstream updates.

## How it is built

```
vendor/sysmon-modular/      upstream, pinned git submodule
wasm/main.go                syscall/js wrapper around upstream's internal packages
tools/build_catalog.py      → site/data/{catalog,fields,upstream}.json   (stdlib Python)
tools/build.sh              runs the generator and compiles the WASM engine into site/
site/                       the static site: index.html + ES modules + Alpine.js + Bootstrap
  js/engine-worker.js       Web Worker hosting the Go/WASM engine (loaded on first use, ~4 MB)
  js/model.js               XML ⇄ rule model (own small parser, no DOM dependency)
  js/catalog.js, search.js, attack.js, state.js, includelist.js
```

The wrapper is copied into `vendor/sysmon-modular/tooling/cmd/vsmwasm/` at build time because the
packages it uses are Go `internal` packages; nothing in the submodule is modified permanently.

### Local development

Requirements: Python 3.12, Node 22 and Go 1.22 (or Docker – `tools/build.sh` falls back to the
`golang` image when `go` is missing).

```bash
git clone --recurse-submodules <this repo>
cd visual-sysmon-modular
tools/build.sh                       # generates site/data and site/wasm
python3 -m http.server -d site 8080  # → http://localhost:8080
```

Tests:

```bash
python3 -m pytest -q tests           # catalog generator
node --test 'tests/js/*.test.mjs'    # model, catalog, search, state, ATT&CK matrix
node tests/wasm_smoke.mjs            # WASM engine end-to-end (merge/validate/coverage/diff)
```

### GitHub Pages deployment

1. In the repository settings → **Pages**, set *Source* to **GitHub Actions**.
2. Push to `main`. `.github/workflows/deploy.yml` builds `site/` and deploys it.
3. Optional: in settings → **Actions → General**, allow GitHub Actions to create pull requests so the
   weekly `upstream.yml` workflow can open "Bump sysmon-modular" PRs. Merging such a PR redeploys the
   site with the new modules; CI runs the WASM smoke test against them first.

## Design

The UI uses the KommuneCERT Bootstrap 5 design system (`site/css/kommunecert-theme.css`);
project-specific styles live in `site/css/app.css`. Bootstrap, Alpine.js and Go's `wasm_exec.js`
are vendored – no CDN dependencies.

## License

This project wraps sysmon-modular, which is licensed under its own terms
(see `vendor/sysmon-modular/license.md`).
