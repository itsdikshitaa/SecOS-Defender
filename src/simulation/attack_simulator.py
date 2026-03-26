import json
import os
from pathlib import Path
from urllib import request


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures" / "demo"
API_BASE_URL = os.getenv("SECOS_API_BASE_URL", "http://localhost:8000/api/v1")


def post_json(path: str, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        f"{API_BASE_URL}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req) as response:
        print(f"[INFO] POST {path} -> {response.status}")


def load_json(filename: str):
    with (FIXTURES / filename).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def send_heartbeat(host_id: str, hostname: str, platform: str) -> None:
    post_json(
        "/agents/heartbeat",
        {
            "host_id": host_id,
            "hostname": hostname,
            "platform": platform,
            "agent_version": "demo-producer",
            "queue_depth": 0,
            "status": "online",
            "metadata": {"producer": "attack_simulator"},
        },
    )


def simulate_inventory() -> None:
    for filename in ["linux-inventory.json", "windows-inventory.json"]:
        report = load_json(filename)
        send_heartbeat(report["host_id"], report["hostname"], report["platform"])
        post_json("/ingest/inventory", report)


def simulate_events() -> None:
    windows_events = load_json("windows-events.json")
    linux_events = load_json("linux-events.json")
    post_json("/ingest/events", {"batch_id": "demo-windows", "events": windows_events})
    post_json("/ingest/events", {"batch_id": "demo-linux", "events": linux_events})


if __name__ == "__main__":
    print("[INFO] Sending SecOS Defender v2 demo inventory...")
    simulate_inventory()
    print("[INFO] Sending SecOS Defender v2 demo events...")
    simulate_events()
    print("[INFO] Demo producer completed. Open the analyst console to inspect findings.")
