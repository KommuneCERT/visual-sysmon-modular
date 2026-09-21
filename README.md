# Visual Sysmon Modular

A browser-only GUI for [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular).
Pick modules per Sysmon event, edit rules in a form or as raw XML, validate, merge and download a
`sysmonconfig.xml` – all inside your browser. Upstream's own Go tooling (merge, validate, analyze,
ATT&CK coverage, semantic diff) is compiled to WebAssembly, so the result is exactly what
`sysmon-modular merge` would produce. Nothing is uploaded anywhere.

**Live site:** https://kommunecert.github.io/visual-sysmon-modular/ – deployed from the `next` branch
(search-first UI). `main` / tag `v1.0-modular-ui` keep the earlier multi-page UI.

## What you can do

The landing page is a search box. You start from sysmon-modular's standard `sysmonconfig.xml`
(the "Balanced" selection) and change it from the search results:

- **Search** as you type – free text, ATT&CK IDs, field names, values, with a small query syntax
  (`-word`, `/regex/`, `"phrase"`, `kind:` `cat:` `event:` `onmatch:` `field:` `op:` `tech:` `value:`).
  Every hit is the matching `<Rule>`/condition in context (module → RuleGroup → event), explained in
  plain words and syntax-highlighted, with a **switch** to take the module in or out of your
  configuration and **Edit / XML** buttons.
- **Rule editor** – RuleGroup → event → Rule → conditions with field/operator dropdowns from the
  Sysmon schema, ATT&CK technique autocomplete with a live tag check, and plain-language explanations.
  Saving validates with upstream's validator. **Raw XML** editor with highlighting for everything else.
- **Overlay** – upstream modules are never changed; your edits and custom modules shadow them.
- **Download sysmonconfig.xml** (footer, or `d`) – merge + schema validation + analyzer in the browser;
  a summary shows findings by severity and a plain-language *Before you deploy* checklist first.
- **Coverage** – live ATT&CK tactic × technique matrix for your configuration, tagged-vs-untagged rule
  stats, Navigator layer export.
- **Help** – workflow, event types (what is on, what each event type costs in volume/CPU/disk/privacy),
  how Sysmon include/exclude filtering works, condition operators, search syntax, shortcuts, deploying.
- **Save / Load** – export your selection and edited modules as one JSON file, import it anywhere,
  reset to the standard configuration, export an `include_rules.txt` for upstream's CLI.

## Where your data lives

In your browser only: your selection and edited modules in `localStorage`.
Clearing site data or switching devices starts from scratch – use **Save / Load** to export a JSON
file and keep it in your own repo. Exports reference upstream modules by path, so they stay valid
across upstream updates.

## How it is built

```
vendor/sysmon-modular/      upstream, pinned git submodule
wasm/main.go                syscall/js wrapper around upstream's internal packages
tools/build_catalog.py      → site/data/{catalog,fields,upstream,attack}.json   (stdlib Python)
tools/build.sh              runs the generator and compiles the WASM engine into site/
site/                       the static site: index.html + ES modules + Alpine.js + Bootstrap
  js/engine-worker.js       Web Worker hosting the Go/WASM engine (loaded on first use, ~4 MB)
  js/model.js               XML ⇄ rule model (own small parser, no DOM dependency)
  js/catalog.js, search.js, describe.js, checks.js, attack.js, state.js, includelist.js
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
# browser end-to-end (needs the static server running and Playwright, see the header of the file):
node tests/e2e/e2e.mjs               # BASE=https://… runs it against a deployed site
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
