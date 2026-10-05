# Project History

A running log of work sessions on Sentinela. Newest sessions at the top.

Each entry records the date, what was done, key decisions, and what's next.

<!--
Entry template:

## YYYY-MM-DD — Short session title

**Done**
- ...

**Decisions**
- ...

**Next**
- ...
-->

---

## 2026-10-05 — History log, Phase 1 cleanup & tests

**Done**
- Added `HISTORY.md` (this file) and `CLAUDE.md` (instructs Claude to update this log every session).
- Reviewed the first working prototype: `server.py` (FastAPI ingest endpoint, 2 single-event rules, Discord alerting) and the demo client.
- Fixed bugs in `server.py`:
  - Process names are normalized to lowercase basename, so full paths like `C:\Windows\System32\whoami.exe` match.
  - `evaluate_rules` returns *all* matching rules; ingest response field `rule` → `rules` (list).
  - `event_type` is a `Literal` (unknown values rejected with 422); `timestamp` is a real `datetime`.
  - Missing `source_ip` reads "an unknown source" instead of "None".
- Webhook URL now loads from `.env` via `python-dotenv`; added `.env.example` (committed) and `.env` (git-ignored).
- Added `.gitignore`, `pyproject.toml` (pytest config), and `tests/test_rules.py` (16 tests, all passing).
- Renamed `test_agent.py` → `send_sample_events.py` (it's a demo script, not a test).
- Verified end to end: server + demo script, benign event → no alert, `whoami.exe` → RULE-001.

**Decisions**
- Keep everything in a single `server.py` until Phase 3 (YAML rules), then split into `agent/` / `server/` / `rules/`.
- Run tests with `python -m pytest`.

**Next**
- Tune noisy rules: `powershell.exe` / `net.exe` should alert on suspicious arguments, not every run; give `mimikatz.exe` its own CRITICAL rule (T1003).
- Decide the primary target (Event ID 4625 failed logon vs 4688 / Sysmon 1 process creation) and align README.
- Later: send alerts via `BackgroundTasks`, API key on `/ingest`, `logging` instead of `print`.

---

## 2026-10-03 — Project kickoff

**Done**
- Created the repository with an MIT `LICENSE` (commit `3373ccd`).
- Wrote the `README.md` project plan (commit `bc3b36b`): overview, tech stack (Python 3.10+, FastAPI, Uvicorn, Pydantic v2, PyYAML, pywin32, Discord/Slack webhooks), system architecture, planned directory layout, and the four-phase MVP roadmap.

**Decisions**
- Build the SIEM pipeline from scratch rather than deploying enterprise tooling.
- First detection target: Windows Event ID `4625` (failed logon), with a sliding-window brute-force threshold rule.
- Detection rules live in human-readable YAML under `rules/`.

**Next**
- Phase 1: Foundation & Schemas.
