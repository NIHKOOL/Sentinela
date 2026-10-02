# Sentinela-SIEM
> A lightweight, modular SIEM and Detection Engineering prototype built from scratch in Python to capture endpoint telemetry, normalize event schemas, and trigger real-time alerts.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Project Overview

**Sentinela** is an ongoing, independent security engineering project designed to demystify and implement the core mechanics of a **Security Information and Event Management (SIEM)** platform. 

Instead of deploying pre-configured enterprise tools, the goal is to build a functional end-to-end telemetry pipeline from the ground up:
* Collecting real-time authentication events from endpoints.
* Normalizing unstructured logs into consistent, validated JSON schemas.
* Running threshold and correlation detection rules against incoming events.
* Dispatching actionable alerts directly to incident triage channels via Webhooks.

---

## Tech Stack & Dependencies

* **Language:** Python 3.10+
* **Backend API:** [FastAPI](https://fastapi.tiangolo.com/) (Asynchronous ingestion endpoint)
* **Server Runner:** [Uvicorn](https://www.uvicorn.org/) (ASGI web server)
* **Data Modeling:** [Pydantic v2](https://docs.pydantic.dev/) (Data validation and normalization)
* **Rule Definitions:** [PyYAML](https://pyyaml.org/) (Declarative detection rule configs)
* **Log Ingestion:** `pywin32` (Windows Event Log queries) / native system file handlers
* **Alerting:** Discord / Slack Incoming Webhooks

---

## System Architecture

```text
+-----------------------+              HTTP POST (JSON)             +-----------------------------+
|   Endpoint / Victim   |  ───────────────────────────────────────► |       Sentinela Core        |
|  (Windows Event Log)  |                                           |     (FastAPI Backend)       |
+-----------------------+                                           +-----------------------------+
           │                                                                       │
           ▼                                                                       ▼
  [ Sentinela Agent ]                                                      [ Normalizer Engine ]
  - Reads Event ID 4625                                                    - Validates schema
  - Packages JSON payload                                                  - Enriches metadata
                                                                                   │
                                                                                   ▼
                                                                           [ Rule Engine ]
                                                                           - Sliding time-window
                                                                           - Correlation checks
                                                                                   │
                                                                                   ▼
                                                                           [ Webhook Dispatcher ]
                                                                                   │
                                                                                   ▼
                                                                           [ Discord / SOC Channel ]
```

---

## Project Structure

```text
sentinela/
├── agent/                         # Endpoint shipper component
│   ├── collectors/                # Event collection scripts (e.g., Windows events)
│   ├── shipper.py                 # Network transmission logic (HTTP POST)
│   └── main.py                    # Agent entrypoint
├── server/                        # Core backend processing
│   ├── api/                       # API routing & ingestion endpoints
│   ├── engine/                    # Parsing, schema normalization & correlation logic
│   ├── alerting/                  # Webhook notification dispatchers
│   └── main.py                    # FastAPI application entrypoint
├── rules/                         # Detection rules stored in human-readable YAML
│   └── brute_force.yaml           # Threshold rule definition
├── tests/                         # Unit tests and synthetic attack scripts
├── requirements.txt               # Project dependencies
└── README.md
```

---

## Target Milestones (MVP Roadmap)

- [ ] **Phase 1: Foundation & Schemas**
  - Define unified JSON schemas using Pydantic for incoming authentication events.
  - Set up basic FastAPI ingestion endpoint (`/api/v1/ingest`).
- [ ] **Phase 2: Agent Telemetry**
  - Implement a Windows Event Log scraper targeting Event ID `4625` (Failed Logon).
  - Stream parsed telemetry to the Sentinela Core backend.
- [ ] **Phase 3: Correlation & Rule Engine**
  - Load detection thresholds from external YAML files.
  - Implement an in-memory sliding time-window (e.g., alert on >5 failed logins from the same source within 60 seconds).
- [ ] **Phase 4: Triage Alerting**
  - Implement automated Discord Webhook dispatching with alert context.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

* **Wattikon Nongnamkhao**
* GitHub: [@NIHKOOL](https://github.com/NIHKOOL)