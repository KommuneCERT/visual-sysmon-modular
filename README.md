# Visual Sysmon Modular

A web GUI on top of [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular).
Instead of hand-editing XML modules and include lists, you pick modules per category, edit rules in a
form (or as raw XML with validation) and press **Build** – upstream's own CLI (`sysmon-modular merge`)
then merges everything into a `sysmonconfig.xml`.

Everything runs in a single Docker container: Python/FastAPI with HTMX/Alpine on the front end and
upstream's Go CLI as the build engine.

## Getting started

```bash
git clone --recurse-submodules <this repo>
cd visual-sysmon-modular
docker compose up -d --build
# → http://localhost:8080
```

The first start creates a **default** profile with every upstream module selected.

## How it works

```
/opt/sysmon-modular   upstream modules (git submodule, read-only inside the container)
/data                 Docker volume with user state
  profiles/<slug>.json       selected modules + build settings
  overlay/<category>/*.xml   edited/custom modules (copy-on-write on top of upstream)
  builds/<profile>/<time>/   sysmonconfig.xml, include_rules.txt, build.log, coverage.json, diff.json
```

- **Search** (start page) – free-text search across the selected modules (or all): module path, RuleGroup name,
  event, rule name, fields, operators, values, ATT&CK IDs. Hits are shown as the matching `<Rule>`/condition
  in context (module → RuleGroup → event) with syntax highlighting and match marking, updated as you type.
- **Profiles** – several independent selections (e.g. `servers`, `workstations`), each with its own
  target Sysmon version (12–15).
- **Categories** – the same directories as upstream (`1_process_creation`, `3_network_connection_initiated`, …).
  Every module can be toggled; "select all / includes / excludes" per category.
- **Rule editor** – RuleGroup → event (include/exclude) → Rule (and/or) → conditions, with field and
  condition dropdowns from the Sysmon schema. Saving validates via `sysmon-modular validate`.
- **Raw XML** – syntax-highlighted editor with *Validate* (same CLI) and "save anyway". All XML views
  (search hits, generated XML, build output) are highlighted by a small dependency-free script.
- **Overlay** – upstream is never touched. Editing an upstream module stores a copy in `overlay/` that
  shadows the original at build time. *Reset to upstream* deletes the copy. Custom modules only live in the overlay.
- **Build** – composes upstream + overlay into a temporary tree and runs
  `sysmon-modular merge --include-list … --sysmon-version … --analyze`. The result page shows findings
  (errors/warnings/performance/recommendations), ATT&CK coverage, a semantic diff against the previous build, and the log.
- **ATT&CK coverage** – live tactic × technique matrix for the current selection (only rules tagged with
  `technique_id=…` count), drill-down to the modules behind each technique, tagged-vs-untagged rule stats and
  a Navigator layer download. The same matrix is shown for every build.
- **Import/export** of include/exclude lists in upstream's text format, so existing setups can be reused.

## Updating upstream

```bash
git submodule update --remote vendor/sysmon-modular
docker compose up -d --build
```

Profiles and the overlay live in the volume and survive both rebuilds and upstream updates.
Modules that disappear upstream are dropped from profiles on the next save.

## Tests

```bash
docker compose build
docker run --rm visual-sysmon-modular:latest python -m pytest -q -p no:cacheprovider
```

The tests run against the real upstream tree and CLI inside the container (parse/serialise, overlay,
profiles, build, HTTP).

## Host directory instead of a named volume

Change the volume in `docker-compose.yml` to `./data:/data` and add `user: "${UID}:${GID}"` to the
service so the container can write to the directory.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_TITLE` | `Visual Sysmon Modular` | Title shown in the navbar |
| `UPSTREAM_DIR` | `/opt/sysmon-modular` | Upstream module tree |
| `DATA_DIR` | `/data` | Profiles, overlay and builds |
| `CLI_BIN` | `/usr/local/bin/sysmon-modular` | Upstream CLI binary |

## Design

The UI uses the KommuneCERT Bootstrap 5 design system (`app/static/kommunecert-theme.css`).
Project-specific styles live in `app/static/app.css` and load after the theme.
Bootstrap, HTMX and Alpine are vendored in `app/static/vendor/` – no CDN dependencies.

## License

This project wraps sysmon-modular, which is licensed under its own terms (see `vendor/sysmon-modular/license.md`).
