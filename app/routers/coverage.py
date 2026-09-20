from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from .. import attack, builder
from ._common import get_profile, render, sidebar_ctx

router = APIRouter()


def _coverage_or_error(profile) -> tuple[dict | None, str]:
    if not profile.modules:
        return None, "The profile has no modules selected."
    out, err, code = builder.run_coverage(profile, "json")
    if code != 0:
        return None, err or out or f"coverage exited with {code}"
    try:
        return json.loads(out), ""
    except json.JSONDecodeError:
        return None, "coverage did not return JSON:\n" + out[:500]


@router.get("/p/{slug}/coverage")
def coverage_page(request: Request, slug: str):
    prof = get_profile(slug)
    cov, err = _coverage_or_error(prof)
    matrix = attack.build_matrix(cov) if cov else None
    tagging = attack.rule_tagging(prof.modules)
    return render(request, "coverage.html", **sidebar_ctx(prof), matrix=matrix, error=err, tagging=tagging)


@router.get("/p/{slug}/coverage.json")
def coverage_json(slug: str):
    prof = get_profile(slug)
    cov, err = _coverage_or_error(prof)
    if cov is None:
        raise HTTPException(400, err)
    return JSONResponse(cov)


@router.get("/p/{slug}/coverage/navigator.json")
def navigator_layer(slug: str, attack_version: str = "19"):
    prof = get_profile(slug)
    if attack_version not in ("18", "19"):
        raise HTTPException(400, "attack_version must be 18 or 19")
    if not prof.modules:
        raise HTTPException(400, "The profile has no modules selected.")
    out, err, code = builder.run_coverage(prof, "navigator", attack_version)
    if code != 0:
        raise HTTPException(500, err or out)
    return Response(out, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{slug}-attack{attack_version}-layer.json"'})
