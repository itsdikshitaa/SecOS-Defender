from datetime import datetime, timedelta

from app.db import SessionLocal
from app.models import ResponseAction
from app.worker import expire_actions


def test_action_lifecycle(auth_client):
    heartbeat = {
        "host_id": "lin-ubuntu-01",
        "hostname": "lin-ubuntu-01",
        "platform": "linux",
        "agent_version": "test",
        "queue_depth": 0,
        "status": "online",
    }
    auth_client.post("/api/v1/agents/heartbeat", json=heartbeat)

    created = auth_client.post(
        "/api/v1/actions",
        json={
            "host_id": "lin-ubuntu-01",
            "type": "isolate_host",
            "parameters": {"reason": "test"},
            "approval_mode": "manual",
            "ttl": 900,
            "requested_by": "pytest",
        },
    ).json()

    action_id = created["action_id"]
    auth_client.post(f"/api/v1/actions/{action_id}/approve", json={"approved_by": "pytest"})

    polled = auth_client.get("/api/v1/actions/poll", params={"host_id": "lin-ubuntu-01"}).json()
    assert polled[0]["action_id"] == action_id

    result = auth_client.post(
        f"/api/v1/actions/{action_id}/result",
        json={"state": "completed", "result": {"message": "done"}},
    )
    assert result.status_code == 200
    assert result.json()["state"] == "completed"


def test_worker_expires_pending_actions_with_sqlite_naive_timestamps(auth_client):
    created = auth_client.post(
        "/api/v1/actions",
        json={
            "host_id": "lin-ubuntu-01",
            "type": "isolate_host",
            "parameters": {"reason": "ttl test"},
            "approval_mode": "manual",
            "ttl": 1,
            "requested_by": "pytest",
        },
    ).json()

    with SessionLocal() as db:
        action = db.get(ResponseAction, created["action_id"])
        action.created_at = datetime.utcnow() - timedelta(seconds=5)
        db.commit()

    assert expire_actions() >= 1

    actions = auth_client.get("/api/v1/actions").json()
    action = next(item for item in actions if item["id"] == created["action_id"])
    assert action["state"] == "expired"
