"""Runtime configuration – every path comes from the environment so the same
image works in docker compose, CI and a local checkout."""
from __future__ import annotations

import os
from pathlib import Path

UPSTREAM_DIR = Path(os.environ.get("UPSTREAM_DIR", "/opt/sysmon-modular"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CLI_BIN = os.environ.get("CLI_BIN", "sysmon-modular")
APP_TITLE = os.environ.get("APP_TITLE", "Visual Sysmon Modular")

PROFILES_DIR = DATA_DIR / "profiles"
OVERLAY_DIR = DATA_DIR / "overlay"
BUILDS_DIR = DATA_DIR / "builds"

SYSMON_VERSIONS = ["15", "14", "13", "12"]
DEFAULT_SYSMON_VERSION = "15"

# Sysmon executable version -> configuration schema version (mirrors upstream merge docs)
SCHEMA_FOR_VERSION = {"12": "4.40", "13": "4.60", "14": "4.83", "15": "4.90"}


def ensure_dirs() -> None:
    for d in (PROFILES_DIR, OVERLAY_DIR, BUILDS_DIR):
        d.mkdir(parents=True, exist_ok=True)
