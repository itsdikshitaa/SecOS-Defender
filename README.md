# 🛡️ SecOS Defender v2

> **A self-hosted endpoint defense platform for Linux and Windows**
>
> Real telemetry. Rule-driven detections. Correlated findings. Controlled response.

![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-1f2937?style=for-the-badge)
![Backend](https://img.shields.io/badge/backend-FastAPI-cb4b16?style=for-the-badge)
![Console](https://img.shields.io/badge/console-React%20%2B%20TypeScript-264653?style=for-the-badge)
![Agent](https://img.shields.io/badge/agent-Go-2a9d8f?style=for-the-badge)
![Database](https://img.shields.io/badge/database-PostgreSQL-e9c46a?style=for-the-badge&labelColor=1f2937)

SecOS Defender v2 transforms this repository from a prototype into a **modern endpoint defense stack**. It combines a **FastAPI detection backend**, a **live analyst console**, a **pluggable Go agent scaffold**, **Sigma-style YAML rule packs**, and **inventory-based vulnerability correlation** into one coherent platform.

This repository is designed for:

- 🔍 Security analysts who need a live triage and investigation surface
- 🧠 Blue-team engineers who want normalized telemetry and rule-driven detection
- ⚙️ Builders who want a strong starting point for a self-hosted EDR/XDR-style product

---

## ✨ What You Get

| Capability | Description |
| --- | --- |
| 🚨 Runtime detections | Normalized event ingestion with rule-based alert generation |
| 🧩 Correlated findings | Deduplicated findings across runtime and vulnerability evidence |
| 📦 Vulnerability intelligence | Software inventory matched against a seeded vulnerability feed |
| 🖥️ Analyst console | React-based UI for alerts, findings, hosts, exposure, and actions |
| 🎛️ Response orchestration | Manual approval flow for host actions such as isolation or artifact collection |
| 📡 Live updates | WebSocket-backed streaming updates with polling fallback |
| 🧪 Demo telemetry | Fixture-driven producer for realistic sample events and inventory |
| 🏗️ Extensible agent | Go agent scaffold with local buffering, polling, and TLS-ready client code |

---

## 🏛️ Architecture

```mermaid
flowchart LR
    A["🛰️ Agent / Demo Producer"] --> B["📥 FastAPI Ingest API"]
    B --> C["🧠 Rule Engine"]
    B --> D["📦 Inventory Correlator"]
    C --> E["🚨 Alerts"]
    C --> F["🧩 Findings"]
    D --> F
    D --> G["🔐 Vulnerabilities"]
    E --> H["📡 WebSocket Stream"]
    F --> H
    G --> H
    H --> I["🖥️ Analyst Console"]
    I --> J["🎛️ Response Actions"]
    J --> B
    B --> K["🗄️ PostgreSQL"]
```

### Core runtime components

- **`server/`**: FastAPI backend, SQLAlchemy models, ingest pipeline, rule engine, worker, and vulnerability feed
- **`console/`**: React + TypeScript analyst console built with Vite
- **`agent/`**: Go-based agent scaffold with fixture collectors, persistent queue, heartbeat, and action loop
- **`rules/default/`**: Sigma-compatible detection packs in YAML
- **`fixtures/demo/`**: Demo events and inventory reports for Linux and Windows
- **`src/simulation/attack_simulator.py`**: Demo producer that sends data into the v2 APIs

---

## 🧠 Product Design

SecOS Defender v2 is built around a few clear principles:

- **High signal first**: the system prioritizes alerts, findings, and exposure that operators can act on
- **Normalized telemetry**: collectors and producers converge on a single event shape
- **Detection as content**: rules are versioned YAML packs rather than hard-coded scripts
- **Self-hosted by default**: everything is designed to run inside your own environment
- **Controlled response**: actions are queued and approved deliberately instead of executed blindly

---

## 📁 Repository Layout

```text
.
├── agent/                  # Go agent scaffold
├── console/                # React/Vite analyst console
├── fixtures/demo/          # Demo event and inventory payloads
├── rules/default/          # YAML rule packs
├── server/                 # FastAPI backend and worker
├── src/simulation/         # Demo producer entrypoint
├── tests/                  # API and integration-oriented tests
├── docker-compose.yml      # Local multi-service startup
└── .env.example            # Example environment variables
```

---

## 🚀 Quick Start

### Option 1: Docker Compose

Bring up PostgreSQL, the API, the worker, and the analyst console:

```bash
docker compose up --build
```

Then open:

- **API health**: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)
- **Analyst console**: [http://localhost:5173](http://localhost:5173)

### Option 2: Local development

#### 1. Backend

Create a virtual environment and install backend dependencies:

```bash
python -m venv .venv
```

**PowerShell**

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r server/requirements.txt
$env:PYTHONPATH = "server"
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**macOS / Linux**

```bash
source .venv/bin/activate
pip install -r server/requirements.txt
export PYTHONPATH=server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

#### 2. Console

```bash
cd console
npm install
npm run dev -- --host 0.0.0.0
```

#### 3. Seed demo data

With the API running:

```bash
python src/simulation/attack_simulator.py
```

The demo producer sends:

- Linux process events that trigger `curl | bash` and dangerous permission change detections
- Windows Sysmon-style PowerShell encoded-command activity
- Software inventory that generates vulnerability findings from the seeded advisory feed

---

## 📡 API Surface

The v2 backend exposes the following primary endpoints:

### Ingest and host state

- `POST /api/v1/ingest/events`
- `POST /api/v1/ingest/inventory`
- `POST /api/v1/agents/heartbeat`

### Response orchestration

- `GET /api/v1/actions/poll`
- `POST /api/v1/actions`
- `POST /api/v1/actions/{id}/approve`
- `POST /api/v1/actions/{id}/result`

### Analyst-facing reads

- `GET /api/v1/overview`
- `GET /api/v1/alerts`
- `GET /api/v1/findings`
- `GET /api/v1/vulnerabilities`
- `GET /api/v1/hosts`
- `GET /api/v1/rules`
- `GET /api/v1/actions`

### Live stream

- `WS /api/v1/ws/stream`

---

## 🧾 Data Model Highlights

The platform is organized around a few key entities:

- **Normalized events**: platform-agnostic telemetry from collectors and producers
- **Alerts**: direct rule-triggered signals
- **Findings**: correlated, deduplicated investigative objects
- **Software inventory**: per-host package and version data
- **Vulnerabilities**: correlated package exposure records
- **Response actions**: analyst-queued operational tasks
- **Audit log**: action lifecycle traceability

The intended runtime datastore is **PostgreSQL**. Tests use **SQLite** for speed and simplicity.

---

## 🧨 Detection Content

Detection packs live in `rules/default/` and follow a Sigma-style structure:

- `id`
- `version`
- `title`
- `status`
- `description`
- `logsource`
- `detection`
- `level`
- `tags`
- `references`
- `mitre_attack`
- `responses`

Included examples detect:

- ⚠️ PowerShell encoded-command execution on Windows
- 🔥 `curl | bash` execution on Linux
- 🔐 Dangerous permission changes on critical Linux files

---

## 🖥️ Analyst Console

The console is not a static mock. It reads real data from the backend and presents:

- **Alert ledger** for current rule output
- **Correlated findings** for analyst triage
- **Exposure watch** for vulnerability-backed risk
- **Host roster** showing active reporting endpoints
- **Response queue** with manual approval workflow

The UI is designed to feel like a **forensic operations workspace**, not a generic dashboard.

---

## 🛰️ Agent

The Go agent scaffold includes:

- Local file-backed event buffering
- Periodic heartbeat reporting
- Fixture-based event and inventory collection
- Action polling and result reporting
- TLS-ready HTTP client wiring

Run it locally with Go installed:

```bash
go run ./agent/cmd/secos-agent -config agent/config.sample.json
```

If you prefer not to install Go locally, you can build it via the included `agent/Dockerfile`.

---

## 🧪 Testing

Run backend tests:

```bash
python -m pytest
```

Current automated coverage includes:

- Event ingest and rule-triggered alert creation
- Idempotent ingest behavior
- Inventory correlation into vulnerability records
- Vulnerability resolution flows
- Response action lifecycle from creation to completion

Build the console for production:

```bash
cd console
npm run build
```

---

## ⚙️ Environment

Example configuration is provided in `.env.example`:

```env
SECOS_DATABASE_URL=postgresql+psycopg://secos:secos@localhost:5432/secos
```

---

## 🧪 Demo Flow

For the fastest way to see the platform working:

1. Start the backend and console
2. Run `python src/simulation/attack_simulator.py`
3. Open the analyst console
4. Inspect:
   - live alerts
   - correlated findings
   - vulnerability exposure
   - queued response actions

---

## 🕰️ Legacy Note

The older prototype modules under `src/` still exist in the repository for historical reference, but the **active v2 platform** is built from:

- `server/`
- `console/`
- `agent/`
- `rules/`
- `fixtures/`

---

## 🤝 Contribution Direction

Strong next steps for contributors:

- Add additional collectors beyond fixtures
- Expand the rule library and ATT&CK mapping
- Introduce richer correlation logic and suppression controls
- Add certificate enrollment and stronger production auth flows
- Extend the response engine with safer allowlisted automations
- Add packaging and deployment hardening for production use

---

## 📜 License

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

## 🌟 Closing

SecOS Defender v2 is a serious foundation for building a **self-hosted, cross-platform endpoint defense product**. It is structured to be understandable, extensible, and immediately runnable while still leaving room for deeper collectors, richer detections, and production-grade operational hardening.
