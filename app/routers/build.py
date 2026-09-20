from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse

from .. import attack, builder
from ._common import get_profile, render, sidebar_ctx

router = APIRouter()


@router.post("/p/{slug}/build")
def run_build(slug: str):
    prof = get_profile(slug)
    meta = builder.run_build(prof)
    return RedirectResponse(f"/p/{slug}/builds/{meta['id']}", status_code=303)


@router.get("/p/{slug}/builds")
def list_builds(request: Request, slug: str):
    prof = get_profile(slug)
    return render(request, "builds.html", **sidebar_ctx(prof), builds=builder.list_builds(slug))


@router.get("/p/{slug}/builds/{build_id}")
def show_build(request: Request, slug: str, build_id: str):
    prof = get_profile(slug)
    meta = builder.load_build(slug, build_id)
    if meta is None:
        raise HTTPException(404, "build not found")
    findings = [builder.Finding(**f) for f in meta["findings"]]
    grouped = {s: [f for f in findings if f.severity == s] for s in builder.SEVERITY_ORDER}
    coverage = builder.read_json(slug, build_id, "coverage.json") if meta.get("has_coverage") else None
    diff = builder.read_json(slug, build_id, "diff.json") if meta.get("has_diff") else None
    log_path = builder.build_path(slug, build_id, "build.log")
    others = [b for b in builder.list_builds(slug) if b["id"] != build_id and b.get("ok")]
    return render(request, "build.html", **sidebar_ctx(prof), build=meta, grouped=grouped,
                  coverage=coverage, matrix=attack.build_matrix(coverage) if coverage else None, diff=diff, log=log_path.read_text() if log_path.exists() else "",
                  other_builds=others)


@router.get("/p/{slug}/builds/{build_id}/diff")
def diff_view(request: Request, slug: str, build_id: str, before: str):
    prof = get_profile(slug)
    meta = builder.load_build(slug, build_id)
    if meta is None or builder.load_build(slug, before) is None:
        raise HTTPException(404)
    diff, err = builder.diff_builds(slug, before, build_id)
    return render(request, "_diff.html", diff=diff, error=err, before_id=before, after_id=build_id)


@router.get("/p/{slug}/builds/{build_id}/xml")
def build_xml_view(request: Request, slug: str, build_id: str):
    get_profile(slug)
    if builder.load_build(slug, build_id) is None:
        raise HTTPException(404)
    p = builder.build_path(slug, build_id, "sysmonconfig.xml")
    if not p.exists():
        raise HTTPException(404)
    return render(request, "_xml_view.html", xml=p.read_text(), auto=True)


@router.get("/p/{slug}/builds/{build_id}/{name}")
def download(slug: str, build_id: str, name: str):
    if name not in ("sysmonconfig.xml", "build.log", "include_rules.txt", "coverage.json", "profile.json"):
        raise HTTPException(404)
    if builder.load_build(slug, build_id) is None:
        raise HTTPException(404)
    p = builder.build_path(slug, build_id, name)
    if not p.exists():
        raise HTTPException(404)
    if name == "sysmonconfig.xml":
        return FileResponse(p, media_type="application/xml", filename=f"sysmonconfig-{slug}-{build_id}.xml")
    return PlainTextResponse(p.read_text())
