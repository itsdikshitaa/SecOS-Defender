def test_inventory_creates_vulnerability_findings(client):
    payload = {
        "host_id": "lin-ubuntu-01",
        "hostname": "lin-ubuntu-01",
        "platform": "linux",
        "packages": [
            {"name": "openssl", "version": "3.0.10", "source": "dpkg"},
            {"name": "curl", "version": "8.6.0", "source": "dpkg"},
        ],
    }
    response = client.post("/api/v1/ingest/inventory", json=payload)
    assert response.status_code == 200
    assert response.json()["vulnerabilities"] == 2

    overview = client.get("/api/v1/overview").json()
    assert len(overview["vulnerabilities"]) == 2
    assert any(item["cve_id"] == "CVE-2024-10001" for item in overview["vulnerabilities"])


def test_inventory_resolution_marks_vulnerability_resolved(client):
    vulnerable = {
        "host_id": "lin-ubuntu-01",
        "hostname": "lin-ubuntu-01",
        "platform": "linux",
        "packages": [{"name": "openssl", "version": "3.0.10", "source": "dpkg"}],
    }
    fixed = {
        "host_id": "lin-ubuntu-01",
        "hostname": "lin-ubuntu-01",
        "platform": "linux",
        "packages": [{"name": "openssl", "version": "3.0.13", "source": "dpkg"}],
    }
    client.post("/api/v1/ingest/inventory", json=vulnerable)
    client.post("/api/v1/ingest/inventory", json=fixed)

    rows = client.get("/api/v1/vulnerabilities").json()
    assert rows[0]["status"] == "resolved"
