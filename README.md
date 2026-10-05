# <img src="web/static/logo-180.png" alt="Sentinela logo" width="42" align="absmiddle"> Sentinela SOC Simulator
> A training simulator for Security Operations: build a virtual organization, play the attacker, then defend it as a SOC analyst using a SIEM built from scratch in Python.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Framework-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Project Overview

**Sentinela** shows how a **SIEM** (Security Information and Event Management) and a **SOC** (Security Operations Center) work, by letting you play both sides:

* **Organization:** a virtual company of workstations and servers that produce normal activity all the time (logons, programs, file copies, the occasional admin task).
* **Attacker:** launch simulated attack steps (password guessing, discovery, credential theft, persistence, lateral movement, exfiltration) against any machine.
* **SOC:** detection rules raise alerts. Work the alert queue, investigate the events, and decide for each alert whether it is a real attack (**true positive**) or normal work (**false positive**).
* **Score:** see which attacks were detected or missed, and how many of your verdicts were right.

**Everything is simulated.** Attack steps only create the log entries such an attack would leave behind, inside the app. Nothing runs on or touches a real computer.

---

## Installation

### Requirements

* **Python 3.10 or newer**: download from [python.org](https://www.python.org/downloads/). On Windows, tick **"Add python.exe to PATH"** in the installer.
* **Git** (optional, to clone the repository): [git-scm.com](https://git-scm.com/downloads). You can also download the project as a ZIP from GitHub.
* A modern web browser (Chrome, Edge, Firefox).

Check your Python version:

```powershell
python --version
```

### 1. Get the code

```powershell
git clone https://github.com/NIHKOOL/Sentinela.git
cd Sentinela
```

### 2. Create a virtual environment (recommended)

A virtual environment keeps Sentinela's packages separate from the rest of your computer.

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

When it is active, your terminal prompt starts with `(.venv)`. Activate it again each time you open a new terminal. `start.bat` uses `.venv` automatically if it exists.

### 3. Install the dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure Discord alerts (optional)

Without this step, alerts only appear in the app.

```powershell
copy .env.example .env      # macOS / Linux: cp .env.example .env
```

1. In Discord, open a channel's settings → **Integrations** → **Webhooks** → **New Webhook** → **Copy Webhook URL**.
2. Paste it into `.env` after `DISCORD_WEBHOOK_URL=` (no spaces or quotes).
3. Optionally set `DISCORD_MIN_SEVERITY` to `LOW`, `MEDIUM`, `HIGH` (default) or `CRITICAL`.

Keep the webhook URL secret. `.env` is ignored by git, so it is never committed.

### 5. Start Sentinela

```powershell
python start.py             # or double-click start.bat on Windows
```

Your browser opens http://127.0.0.1:8000. Stop the server with **Ctrl+C** in the terminal.

### 6. Check that it works (optional)

```powershell
python -m pytest
```

All tests should pass.

### Troubleshooting

| Problem | Solution |
|---|---|
| `'python' is not recognized` | Python is not on your PATH. Reinstall Python and tick **"Add python.exe to PATH"**, or use `py` instead of `python`. |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once in PowerShell, then activate again. |
| `[Errno 10048] ... only one usage of each socket address` | Port 8000 is already in use, usually by another Sentinela window. Close it, or stop it with Ctrl+C. |
| `ModuleNotFoundError: No module named 'fastapi'` (or `dotenv`) | The dependencies are not installed in the Python you are using. Activate `.venv` and run `pip install -r requirements.txt` again. |
| The page looks outdated after an update | Press **Ctrl+F5** to reload it without the browser cache. |
| The top bar says **Discord off** | Check `.env` (step 4), then restart Sentinela. `.env` is only read at startup. |

---

## Getting Started

Once Sentinela is running at http://127.0.0.1:8000:

1. **Organization:** look at the sample company, or add your own computers and servers.
2. **Attacker:** pick an attack step and a target, and launch it. Try the full chain shown on the page.
3. **SOC:** open alerts, investigate, and close each one as a true or false positive.
4. **Overview:** check the scoreboard and the detection rules.

The interactive API docs are at http://127.0.0.1:8000/docs. Run the tests with `python -m pytest`.

---

## How It Works

```text
 Organization ──► Activity ──────────────┐
 (assets)         normal work, every Ns  │
                                         ▼
 Attacker ───► simulated attack steps ─► Event pipeline ─► Detection rules ─► Alerts ─► SOC triage ─► Score
                                         ▲  (normalize,     (single-event +    (grouped,   (true/false   (compare with
 Real agents ──► POST /api/v1/ingest ────┘   store)          correlation)       Discord)    positive)     ground truth)
```

* Every event uses one normalized schema (`TelemetryEvent`), whether it is background noise, an attack step or a real event sent to `/api/v1/ingest`.
* **Correlation rules** remember earlier events: 5 failed logons from one source within 60 seconds is a brute force (SEN-003), and a successful logon from that source afterwards is critical (SEN-004).
* Repeated matches of the same rule for the same host, user and source are **grouped** into one alert, like a real SIEM.
* The simulation remembers which events came from the attacker (**ground truth**), but the SOC views never show it. The score compares your verdicts with the truth.
* Some normal activity triggers rules on purpose (an admin running `whoami`, IT creating an account, a big upload to cloud storage), so the SOC must learn to tell false positives apart.
* Not every attack step has a rule: **lateral movement goes undetected** by default. Finding and closing gaps like this is the job of detection engineering.

### Detection rules · [MITRE ATT&CK documentation](https://attack.mitre.org/)

| Rule | Severity | Detects | MITRE |
|---|---|---|---|
| SEN-001 | Medium | Discovery commands (whoami, net, nltest, systeminfo) | [T1033](https://attack.mitre.org/techniques/T1033/) / [T1087](https://attack.mitre.org/techniques/T1087/) |
| SEN-002 | Low | Failed logon for administrator / admin / root | [T1110](https://attack.mitre.org/techniques/T1110/) |
| SEN-003 | High | Brute force: 5+ failed logons from one source in 60s | [T1110](https://attack.mitre.org/techniques/T1110/) |
| SEN-004 | Critical | Successful logon after brute force | [T1110](https://attack.mitre.org/techniques/T1110/) / [T1078](https://attack.mitre.org/techniques/T1078/) |
| SEN-005 | Critical | Known credential theft tool | [T1003](https://attack.mitre.org/techniques/T1003/) |
| SEN-006 | Medium | New user account created | [T1136](https://attack.mitre.org/techniques/T1136/) |
| SEN-007 | High | 50 MB+ upload to an external IP | [T1048](https://attack.mitre.org/techniques/T1048/) |

---

## Tech Stack & Dependencies

* **Language:** Python 3.10+
* **Backend API:** [FastAPI](https://fastapi.tiangolo.com/), served by [Uvicorn](https://www.uvicorn.org/)
* **Data Modeling:** [Pydantic v2](https://docs.pydantic.dev/) (validation and normalization)
* **Frontend:** plain HTML, CSS and JavaScript (no build step)
* **Alerting:** Discord incoming webhooks (optional)
* **Tests:** pytest

---

## Project Structure

```text
Sentinela/
├── sentinela/                 # Python package (the SIEM + simulation)
│   ├── api.py                 # FastAPI app: REST API and web pages
│   ├── models.py              # Event, asset and request schemas
│   ├── organization.py        # Virtual company (saved to data/organization.json)
│   ├── activity.py            # Normal background activity and false-positive sources
│   ├── attacks.py             # Attacker playbook: simulated attack steps
│   ├── detection.py           # Detection rules (single-event + correlation)
│   ├── simulation.py          # Event pipeline, alert grouping, triage, scoring
│   └── alerting.py            # Discord notifications
├── web/                       # Pages: Overview, Organization, SOC, Attacker
│   └── static/                # Shared CSS, JavaScript and logo (logo.png + resized copies)
├── tests/                     # pytest suite
├── start.py / start.bat       # Start the server and open the browser
├── requirements.txt
└── README.md
```

---

## Roadmap

- [x] Normalized event schema, ingestion API and detection rules
- [x] Virtual organization, background activity and attacker scenarios
- [x] SOC console with alert grouping, triage and scoring
- [x] Correlation rules (brute force, logon after brute force)
- [ ] Rules in YAML files, editable without changing code
- [ ] A rule that catches lateral movement
- [ ] Save events and alerts in SQLite so a game survives restarts
- [ ] Real Windows agent that sends Event Log data to `/api/v1/ingest`

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

* **Wattikon Nongnamkhao**
* GitHub: [@NIHKOOL](https://github.com/NIHKOOL)
