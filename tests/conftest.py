import os
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="vsm-test-")
os.environ["DATA_DIR"] = _tmp
os.environ.setdefault("UPSTREAM_DIR", "/opt/sysmon-modular")
os.environ.setdefault("CLI_BIN", "/usr/local/bin/sysmon-modular")

from app import config  # noqa: E402  (after env is set)


@pytest.fixture(autouse=True)
def fresh_data(monkeypatch):
    """Each test gets an empty DATA_DIR."""
    d = Path(tempfile.mkdtemp(prefix="vsm-data-"))
    monkeypatch.setattr(config, "DATA_DIR", d)
    monkeypatch.setattr(config, "PROFILES_DIR", d / "profiles")
    monkeypatch.setattr(config, "OVERLAY_DIR", d / "overlay")
    monkeypatch.setattr(config, "BUILDS_DIR", d / "builds")
    config.ensure_dirs()
    yield d


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c
