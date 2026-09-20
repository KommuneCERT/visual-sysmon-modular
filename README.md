# Visual Sysmon Modular

Web-GUI oven på [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular).
I stedet for at rette XML-moduler og include-lister i hånden vælger man moduler pr. kategori,
redigerer regler i en formular (eller som rå XML med validering) og trykker **Build** –
så merger upstreams eget CLI (`sysmon-modular merge`) det hele til en `sysmonconfig.xml`.

Alt kører i én Docker-container: Python/FastAPI + HTMX/Alpine i frontend, upstreams Go-CLI som build-motor.

## Kom i gang

```bash
git clone --recurse-submodules <dette repo>
cd visual-sysmon-modular
docker compose up -d --build
# → http://localhost:8080
```

Første start opretter profilen **default** med alle upstream-moduler valgt.

## Sådan virker det

```
/opt/sysmon-modular   upstream-moduler (git-submodule, read-only i containeren)
/data                 Docker-volume med brugerens tilstand
  profiles/<slug>.json    valgte moduler + build-indstillinger
  overlay/<kategori>/*.xml   redigerede/egne moduler (copy-on-write oven på upstream)
  builds/<profil>/<tid>/  sysmonconfig.xml, include_rules.txt, build.log, coverage.json, diff.json
```

- **Profiler** – flere uafhængige valg (fx `servers`, `workstations`) med hver sin Sysmon-målversion (12–15).
- **Kategorier** – de samme mapper som upstream (`1_process_creation`, `3_network_connection_initiated`, …).
  Hvert modul kan slås til/fra; "Vælg alle / kun includes / kun excludes" pr. kategori.
- **Regel-editor** – RuleGroup → event (include/exclude) → Rule (and/or) → betingelser, med felt-
  og condition-dropdowns fra Sysmon-skemaet. Gem validerer via `sysmon-modular validate`.
- **Rå XML** – tekst-editor med *Validér* (samme CLI) og "gem alligevel".
- **Overlay** – upstream røres aldrig. Redigerer man et upstream-modul, gemmes en kopi i `overlay/`,
  som skygger for originalen ved build. *Nulstil til upstream* sletter kopien. Egne moduler oprettes kun i overlay.
- **Build** – komponerer upstream + overlay til et midlertidigt træ og kører
  `sysmon-modular merge --include-list … --sysmon-version … --analyze`. Resultatsiden viser fund
  (fejl/advarsler/performance/anbefalinger), ATT&CK-coverage, semantisk diff mod forrige build og log.
- **Import/eksport** af include-/exclude-lister i upstreams tekstformat, så eksisterende opsætninger kan genbruges.

## Opdatér upstream

```bash
git submodule update --remote vendor/sysmon-modular
docker compose up -d --build
```

Profiler og overlay ligger i volumen og overlever både rebuild og upstream-opdateringer.
Moduler der forsvinder upstream fjernes automatisk fra profiler ved næste gem.

## Tests

```bash
docker compose build
docker run --rm visual-sysmon-modular:latest python -m pytest -q -p no:cacheprovider
```

Testene kører mod det rigtige upstream-træ og CLI i containeren (parse/serialise, overlay, profiler, build, HTTP).

## Data på host i stedet for named volume

Byt volumen i `docker-compose.yml` til `./data:/data` og tilføj `user: "${UID}:${GID}"` på servicen,
så containeren kan skrive i mappen.

## Design

UI'et bruger KommuneCERTs Bootstrap 5-designsystem (`app/static/kommunecert-theme.css`, kopieret fra
`../stylesheet/`). Projekt-specifikke tilpasninger ligger i `app/static/app.css` og indlæses efter theme'et.
Bootstrap, HTMX og Alpine er vendored i `app/static/vendor/` – ingen CDN-afhængigheder.
