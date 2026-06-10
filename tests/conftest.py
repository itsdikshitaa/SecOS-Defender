import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SERVER_ROOT = ROOT / "server"
sys.path.insert(0, str(SERVER_ROOT))
os.environ["SECOS_DATABASE_URL"] = f"sqlite:///{ROOT / 'test_secos_v2.db'}"
os.environ["SECOS_API_KEY"] = "secos-dev-key-change-in-production"

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.bootstrap import bootstrap  # noqa: E402


_API_KEY_HEADER = {"X-API-Key": "secos-dev-key-change-in-production"}


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            bootstrap(app.state.rule_engine, app.state.vulnerability_service, db)
        yield test_client
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def auth_client(client):
    """TestClient that automatically includes the API key header."""
    client.headers.update(_API_KEY_HEADER)
    return client
