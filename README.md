# SecOS Defender v2

SecOS Defender v2 is a self-hosted endpoint defense platform for Linux and Windows. This repository now includes:

- A FastAPI backend with normalized event ingestion, rule-driven detections, vulnerability correlation, response orchestration, and WebSocket updates
- A React/TypeScript analyst console for alerts, findings, host inventory, exposure tracking, and action approval
- A Go agent scaffold with persistent buffering, fixture-based collectors, heartbeats, ingest, and action result reporting
- Docker Compose for local bring-up with PostgreSQL
- Demo fixtures and a Python producer that sends realistic sample telemetry into the new API

## Architecture

- `server/`: FastAPI API, SQLAlchemy models, rule engine, worker, vulnerability feed
- `console/`: React/Vite analyst console
- `agent/`: Go agent skeleton with TLS-ready client and local queue
- `rules/default/`: Sigma-compatible YAML detection packs
- `fixtures/demo/`: Demo events and inventory
- `src/simulation/attack_simulator.py`: Demo producer for the v2 ingest API

## Quick Start

### Option 1: Docker Compose

```bash
docker compose up --build
```

Then open:

- API: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)
- Console: [http://localhost:5173](http://localhost:5173)

### Option 2: Local development

Backend:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r server/requirements.txt
set PYTHONPATH=server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Console:

```bash
cd console
npm install
npm run dev -- --host 0.0.0.0
```

## Seed Demo Data

With the API running:

```bash
python src/simulation/attack_simulator.py
```

This sends:

- Linux runtime events that trigger `curl | bash` and dangerous `chmod` detections
- Windows Sysmon-like PowerShell events
- Package inventory that creates vulnerability findings from the seeded feed

## Agent

The Go agent is scaffolded for fixture-backed collection and action polling:

```bash
go run ./agent/cmd/secos-agent -config agent/config.sample.json
```

Go is not bundled in this repo. If Go is unavailable locally, build the agent with the included `agent/Dockerfile`.

## Tests

```bash
python -m pytest
```

## Notes

- PostgreSQL is the intended runtime datastore; tests default to SQLite for speed.
- The old prototype modules under `src/` remain in the repo as historical reference, but the active v2 stack is `server/`, `console/`, and `agent/`.
