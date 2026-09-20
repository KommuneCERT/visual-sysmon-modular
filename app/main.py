from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import builder, catalog, config, profiles
from .routers import build, coverage, modules, profiles as profiles_router

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
templates.env.globals.update(
    app_title=config.APP_TITLE,
    sysmon_versions=config.SYSMON_VERSIONS,
    schema_for_version=config.SCHEMA_FOR_VERSION,
)

@asynccontextmanager
async def _lifespan(app: FastAPI):
    config.ensure_dirs()
    profiles.ensure_default()
    app.state.cli_version = builder.cli_version()
    yield


app = FastAPI(title=config.APP_TITLE, lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
app.state.templates = templates


@app.get("/", include_in_schema=False)
def index() -> RedirectResponse:
    prof = profiles.ensure_default()
    return RedirectResponse(f"/p/{prof.slug}/", status_code=303)


@app.get("/help", include_in_schema=False)
def help_redirect() -> RedirectResponse:
    prof = profiles.ensure_default()
    return RedirectResponse(f"/p/{prof.slug}/help", status_code=303)


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    return {"ok": True, "cli": app.state.cli_version, "categories": len(catalog.category_dirs())}


app.include_router(profiles_router.router)
app.include_router(modules.router)
app.include_router(build.router)
app.include_router(coverage.router)
