from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import catalog, profiles


def render(request: Request, name: str, **ctx) -> HTMLResponse:
    ctx.setdefault("cli_version", getattr(request.app.state, "cli_version", ""))
    return request.app.state.templates.TemplateResponse(request, name, ctx)


def get_profile(slug: str) -> profiles.Profile:
    try:
        return profiles.load(slug)
    except (FileNotFoundError, ValueError):
        raise HTTPException(404, f"profile '{slug}' not found")


def sidebar_ctx(profile: profiles.Profile, active: str | None = None) -> dict:
    cats = catalog.scan()
    selected = profile.selected
    rows = []
    for c in cats:
        n_sel = sum(1 for m in c.modules if m.rel in selected)
        rows.append({"cat": c, "selected": n_sel, "total": len(c.modules)})
    return {
        "profile": profile,
        "all_profiles": profiles.list_profiles(),
        "sidebar": rows,
        "active_category": active,
        "selected_total": len(selected),
        "module_total": sum(len(c.modules) for c in cats),
    }
