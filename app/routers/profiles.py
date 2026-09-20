from __future__ import annotations

from fastapi import APIRouter, Form, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse

from .. import builder, catalog, config, overlay, profiles
from ._common import get_profile, render, sidebar_ctx

router = APIRouter()


@router.get("/p/{slug}/")
def dashboard(request: Request, slug: str):
    prof = get_profile(slug)
    ctx = sidebar_ctx(prof)
    return render(
        request, "dashboard.html", **ctx,
        builds=builder.list_builds(slug)[:10],
        overlay_files=overlay.overlay_files(),
        flash=request.query_params.get("msg", ""),
    )


@router.get("/p/{slug}/help")
def help_page(request: Request, slug: str):
    prof = get_profile(slug)
    return render(request, "help.html", **sidebar_ctx(prof))


@router.post("/profiles")
def create_profile(name: str = Form(...), mode: str = Form("all"), copy_from: str = Form("")):
    try:
        if copy_from:
            src = profiles.load(copy_from)
            prof = profiles.create(name, select_all=False, sysmon_version=src.sysmon_version,
                                   unsupported=src.unsupported, preserve_comments=src.preserve_comments,
                                   force_grouprelation_or=src.force_grouprelation_or, analyze=src.analyze)
            prof.modules = list(src.modules)
            profiles.save(prof)
        else:
            prof = profiles.create(name, select_all=(mode == "all"))
    except FileExistsError:
        return RedirectResponse(f"/?msg=Profile+already+exists", status_code=303)
    except ValueError as exc:
        return RedirectResponse(f"/?msg={exc}", status_code=303)
    return RedirectResponse(f"/p/{prof.slug}/", status_code=303)


@router.post("/p/{slug}/settings")
def update_settings(
    slug: str,
    name: str = Form(...),
    description: str = Form(""),
    sysmon_version: str = Form(config.DEFAULT_SYSMON_VERSION),
    unsupported: str = Form("warn"),
    preserve_comments: bool = Form(False),
    force_grouprelation_or: bool = Form(False),
    analyze: bool = Form(False),
):
    prof = get_profile(slug)
    prof.name = name.strip() or prof.name
    prof.description = description.strip()
    prof.sysmon_version = sysmon_version if sysmon_version in config.SYSMON_VERSIONS else prof.sysmon_version
    prof.unsupported = unsupported if unsupported in ("warn", "exclude") else "warn"
    prof.preserve_comments = preserve_comments
    prof.force_grouprelation_or = force_grouprelation_or
    prof.analyze = analyze
    profiles.save(prof)
    return RedirectResponse(f"/p/{slug}/?msg=Settings+saved", status_code=303)


@router.post("/p/{slug}/delete")
def delete_profile(slug: str):
    profiles.delete(slug)
    return RedirectResponse("/", status_code=303)


@router.post("/p/{slug}/select-all")
def select_all(slug: str, mode: str = Form("all")):
    prof = get_profile(slug)
    rels = catalog.all_module_rels()
    if mode == "all":
        prof.modules = rels
    elif mode == "none":
        prof.modules = []
    elif mode in ("include", "exclude"):
        prof.modules = [r for r in rels if r.split("/")[1].startswith(mode + "_")]
    profiles.save(prof)
    return RedirectResponse(f"/p/{slug}/", status_code=303)


@router.post("/p/{slug}/import")
async def import_list(slug: str, file: UploadFile, mode: str = Form("replace")):
    prof = get_profile(slug)
    text = (await file.read()).decode("utf-8", errors="replace")
    rels = profiles.parse_list(text)
    if mode == "exclude":
        prof.modules = [m for m in prof.modules if m not in set(rels)]
    elif mode == "add":
        prof.modules = sorted(set(prof.modules) | set(rels))
    else:
        prof.modules = rels
    profiles.save(prof)
    return RedirectResponse(f"/p/{slug}/?msg={len(rels)}+modules+processed", status_code=303)


@router.get("/p/{slug}/include_rules.txt")
def export_list(slug: str):
    prof = get_profile(slug)
    return PlainTextResponse(profiles.to_include_list(prof),
                             headers={"Content-Disposition": f'attachment; filename="{slug}_include_rules.txt"'})
