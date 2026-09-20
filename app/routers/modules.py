from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import builder, catalog, config, overlay, profiles, sysmon_xml
from ._common import get_profile, render, sidebar_ctx

router = APIRouter()


def _module_or_404(rel: str) -> catalog.Module:
    try:
        if not overlay.exists(rel):
            raise FileNotFoundError(rel)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return catalog.get_module(rel)


# ── category view ────────────────────────────────────────────────────────────
@router.get("/p/{slug}/c/{category}")
def category_view(request: Request, slug: str, category: str):
    prof = get_profile(slug)
    cat = catalog.get_category(category)
    if cat is None:
        raise HTTPException(404, "category not found")
    q = request.query_params.get("q", "").strip().lower()
    kind = request.query_params.get("kind", "")
    mods = cat.modules
    if kind in ("include", "exclude"):
        mods = [m for m in mods if m.kind == kind]
    if q:
        mods = [m for m in mods if q in m.filename.lower() or q in m.title.lower()
                or any(q in t[0].lower() or q in t[1].lower() for t in m.techniques)]
    return render(request, "category.html", **sidebar_ctx(prof, active=category),
                  category=cat, modules=mods, q=q, kind=kind, flash=request.query_params.get("msg", ""))


@router.post("/p/{slug}/toggle")
def toggle(request: Request, slug: str, rel: str = Form(...), on: bool = Form(False)):
    prof = get_profile(slug)
    mod = _module_or_404(rel)
    sel = prof.selected
    if on:
        sel.add(rel)
    else:
        sel.discard(rel)
    prof.modules = sorted(sel)
    profiles.save(prof)
    # HTMX: return the card plus an out-of-band sidebar refresh
    ctx = sidebar_ctx(prof, active=mod.category)
    return render(request, "_toggle_response.html", **ctx, m=mod, selected=sel)


@router.post("/p/{slug}/c/{category}/select")
def select_category(slug: str, category: str, mode: str = Form("all")):
    prof = get_profile(slug)
    rels = catalog.module_rels(category)
    sel = prof.selected
    if mode == "all":
        sel |= set(rels)
    elif mode == "none":
        sel -= set(rels)
    elif mode in ("include", "exclude"):
        sel |= {r for r in rels if r.split("/")[1].startswith(mode + "_")}
    prof.modules = sorted(sel)
    profiles.save(prof)
    return RedirectResponse(f"/p/{slug}/c/{category}", status_code=303)


# ── new / duplicate / revert ─────────────────────────────────────────────────
@router.get("/p/{slug}/c/{category}/new")
def new_module_form(request: Request, slug: str, category: str):
    prof = get_profile(slug)
    cat = catalog.get_category(category)
    if cat is None:
        raise HTTPException(404)
    default_event = next((et for m in cat.modules for et in m.event_types), sysmon_xml.EVENT_TYPES[0])
    return render(request, "new_module.html", **sidebar_ctx(prof, active=category),
                  category=cat, event_types=sysmon_xml.EVENT_TYPES, default_event=default_event, schema=sysmon_xml.SCHEMA)


@router.post("/p/{slug}/c/{category}/new")
def new_module(slug: str, category: str, name: str = Form(...), kind: str = Form("include"),
               event_type: str = Form(...)):
    prof = get_profile(slug)
    if event_type not in sysmon_xml.EVENT_TYPES:
        raise HTTPException(400, "unknown event type")
    try:
        rel = overlay.new_module(category, kind, name, event_type,
                                 schemaversion=config.SCHEMA_FOR_VERSION.get(prof.sysmon_version, "4.90"))
    except FileExistsError as exc:
        return RedirectResponse(f"/p/{slug}/c/{category}?msg=Module+already+exists:+{exc}", status_code=303)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    prof.modules = sorted(prof.selected | {rel})
    profiles.save(prof)
    return RedirectResponse(f"/p/{slug}/m/{rel}/edit", status_code=303)


@router.post("/p/{slug}/m/{rel:path}/duplicate")
def duplicate(slug: str, rel: str, name: str = Form(...)):
    prof = get_profile(slug)
    _module_or_404(rel)
    try:
        new_rel = overlay.duplicate(rel, name)
    except FileExistsError as exc:
        return RedirectResponse(f"/p/{slug}/c/{rel.split('/')[0]}?msg=Already+exists:+{exc}", status_code=303)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    prof.modules = sorted(prof.selected | {new_rel})
    profiles.save(prof)
    return RedirectResponse(f"/p/{slug}/m/{new_rel}/edit", status_code=303)


@router.post("/p/{slug}/m/{rel:path}/revert")
def revert(slug: str, rel: str):
    prof = get_profile(slug)
    mod = _module_or_404(rel)
    overlay.revert(rel)
    if not overlay.exists(rel):          # custom module deleted → drop from every profile
        for p in profiles.list_profiles():
            if rel in p.modules:
                p.modules = [m for m in p.modules if m != rel]
                profiles.save(p)
    return RedirectResponse(f"/p/{slug}/c/{mod.category}?msg=Module+reset", status_code=303)


# ── structured editor ────────────────────────────────────────────────────────
@router.get("/p/{slug}/m/{rel:path}/edit")
def edit_module(request: Request, slug: str, rel: str):
    prof = get_profile(slug)
    mod = _module_or_404(rel)
    try:
        parsed = sysmon_xml.parse(overlay.read_text(rel))
    except Exception as exc:
        return RedirectResponse(f"/p/{slug}/m/{rel}/raw?msg=Cannot+be+parsed+structurally:+{exc}", status_code=303)
    return render(request, "editor.html", **sidebar_ctx(prof, active=mod.category),
                  m=mod, model=parsed.to_dict(), schema=sysmon_xml.SCHEMA,
                  flash=request.query_params.get("msg", ""))


@router.post("/p/{slug}/m/{rel:path}/edit")
async def save_module(request: Request, slug: str, rel: str):
    prof = get_profile(slug)
    _module_or_404(rel)
    body = await request.json()
    try:
        mod = sysmon_xml.Module.from_dict(body.get("model", {}))
    except (KeyError, TypeError) as exc:
        return JSONResponse({"ok": False, "error": f"invalid model: {exc}"}, status_code=400)
    for rg in mod.rulegroups:
        for ev in rg.events:
            if ev.event_type not in sysmon_xml.EVENT_TYPES:
                return JSONResponse({"ok": False, "error": f"unknown event type {ev.event_type}"}, status_code=400)
    xml = sysmon_xml.to_xml(mod)
    findings, code = builder.validate_text(xml, prof.sysmon_version)
    errors = [f for f in findings if f.severity == "error"]
    if errors and not body.get("force"):
        return JSONResponse({"ok": False, "saved": False, "findings": [f.__dict__ for f in findings]})
    overlay.write_text(rel, xml)
    return JSONResponse({"ok": True, "saved": True, "findings": [f.__dict__ for f in findings], "xml": xml})


# ── raw XML editor ───────────────────────────────────────────────────────────
@router.get("/p/{slug}/m/{rel:path}/raw")
def raw_module(request: Request, slug: str, rel: str):
    prof = get_profile(slug)
    mod = _module_or_404(rel)
    return render(request, "raw.html", **sidebar_ctx(prof, active=mod.category),
                  m=mod, xml=overlay.read_text(rel), flash=request.query_params.get("msg", ""))


@router.post("/p/{slug}/m/{rel:path}/validate")
def validate_module(request: Request, slug: str, rel: str, xml: str = Form(...)):
    prof = get_profile(slug)
    findings, code = builder.validate_text(xml, prof.sysmon_version)
    return render(request, "_findings.html", findings=findings, summary=builder.summarize(findings),
                  exit_code=code, compact=True)


@router.post("/p/{slug}/m/{rel:path}/raw")
def save_raw(request: Request, slug: str, rel: str, xml: str = Form(...), force: bool = Form(False)):
    prof = get_profile(slug)
    mod = _module_or_404(rel)
    ok, err = sysmon_xml.is_well_formed(xml)
    findings: list[builder.Finding] = []
    code = 0
    if ok:
        findings, code = builder.validate_text(xml, prof.sysmon_version)
    has_errors = (not ok) or any(f.severity == "error" for f in findings)
    if has_errors and not force:
        return render(request, "raw.html", **sidebar_ctx(prof, active=mod.category), m=mod, xml=xml,
                      findings=findings, summary=builder.summarize(findings), exit_code=code,
                      parse_error=err, flash="Not saved – fix the errors or choose 'Save anyway'.")
    overlay.write_text(rel, xml if xml.endswith("\n") else xml + "\n")
    return RedirectResponse(f"/p/{slug}/m/{rel}/raw?msg=Saved+to+overlay", status_code=303)
