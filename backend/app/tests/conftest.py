from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import db  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("AGENT_SHIELD_DB_PATH", str(db_path))
    db.init_db()
    db.clear_all()
    return db_path


@pytest.fixture()
def client(isolated_db: Path) -> TestClient:
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client

