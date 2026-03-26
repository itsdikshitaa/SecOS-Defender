import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
SERVER_ROOT = ROOT / "server"
sys.path.insert(0, str(SERVER_ROOT))
os.environ["SECOS_DATABASE_URL"] = f"sqlite:///{ROOT / 'test_secos_v2.db'}"

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.bootstrap import bootstrap  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        with SessionLocal() as db:
            bootstrap(app.state.rule_engine, app.state.vulnerability_service, db)
        yield test_client
        Base.metadata.drop_all(bind=engine)
