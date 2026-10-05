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

## 2026-10-06 — Logo, Discord, README install guide, YAML (Sigma-style) rules

**Done**
- Added the project logo (`web/static/logo.png`, moved from `Logo.png` in the repo root): app icon in the top-left header of every page, browser favicon (`<link rel="icon">` + a `/favicon.ico` route so browsers stop logging 404s), and in front of the README title. Resized copies (`logo-32.png`, `logo-64.png`, `logo-180.png`, made with Windows System.Drawing) are used for favicon, header and README; `logo.png` is kept as the full-size source. Tests: 60 passing.
- Removed the logo from the page header (favicon and README logo kept).
- The "Discord on/off" status chip is now in the top bar of every page (was SOC only); its update code moved to `common.js`.
- README: added an **Installation** section (requirements, clone, virtual environment, dependencies, Discord setup, start, tests, troubleshooting table); the old quick-start block became "Getting Started" usage steps. `start.bat` now uses `.venv\Scripts\python.exe` when a virtual environment exists.
- Security check before committing: no secrets in files to commit or in git history; `.gitignore` hardened (`.env.*` except `.env.example`, `.claude/settings.local.json`). Found two low-risk local issues not yet fixed: cross-site POST can reset the game/organization (CSRF), and any Host header is accepted (DNS rebinding).
- Fixed stale browser cache: the browser kept an old `common.js`, so the Discord chip never updated. Pages and static files are now served with `Cache-Control: no-cache` (revalidated via ETag on every load).
- Top navigation bar is now sticky (stays visible while scrolling). The SOC alert-details panel sticks just below it, and stops sticking on narrow screens where the layout is one column. Removed the large duplicate logo next to the Overview title.
- Explained terminal output (Uvicorn access log lines from the pages' polling vs. `[!] ALERT` lines), that the organization is fully simulated, and how to connect a Discord webhook via `.env`.

- **Detection rules moved to Sigma-style YAML** (`rules/*.yml`):
  - `sentinela/rules.py`: loader + compiler using `yaml.safe_load`. Supports logsource categories, selections (mapping / list of mappings / keywords), modifiers (contains, startswith, endswith, re, cidr, gt/gte/lt/lte, exists, all), wildcards, and conditions (and/or/not/parentheses/`1 of`/`all of`/`them`). Correlations: event_count, value_count, temporal, temporal_ordered with group-by and timespan. Broken rules are skipped with a clear error; others keep working.
  - `sentinela/detection.py`: now runs the loaded ruleset and keeps correlation state; `RULES` dict and hard-coded rule logic removed.
  - The 7 rules converted 1:1 (SEN-003/004 are correlations built on name-only "building block" rules). Old detection tests pass unchanged against the YAML rules.
  - `POST /api/v1/rules/reload` + **Reload rules** button; Overview shows rule type, file and load errors; SOC alert details show the rule's known false positives. `GET /api/v1/rules` now returns `{directory, rules, errors}`.
  - `rules/README.md`: rule-writing guide with a verified lateral movement exercise (SEN-008, 0 false positives in 300 background ticks). Added `pyyaml>=6.0`. Tests: 133 passing.

- Committed by the user on `main`: `2ded1b6` (feat: YAML rules) and `b1fb0a8` (docs).
- The user started writing their **own first rule**: `rules/sen-008-Search-file-Directory.yml` (T1083 File and Directory Discovery). **Not committed, and currently skipped by the loader** because of `logsource: category: file_access` (Sentinela has no file events). Its detection block is still the guide's example (whoami/net), which duplicates SEN-001. A corrected version was explained in chat and tested in a temp folder (not written to the file):
  - `category: process_creation`
  - `search_programs` (`process_file`: tree.com, findstr.exe, where.exe, forfiles.exe, find, locate)
  - `search_commands` (`command_line|contains`: 'dir /s', 'Get-ChildItem -Recurse', 'gci -r')
  - `filter_it` (user it-admin); condition `1 of search_* and not filter_it`; `level: low`
  - Verified: catches `dir /s`, `findstr /si password`, `Get-ChildItem -Recurse`; ignores Excel, plain `dir`, it-admin.

**Decisions**
- Sentinela deviation from Sigma: a rule raises alerts only if it has an `id`; `name`-only rules are building blocks (instead of Sigma's `generate`). Field names are Sentinela's own, with common Sigma aliases (Image, CommandLine, ...).
- The lateral movement rule stays an exercise for the user (documented in `rules/README.md`), not shipped.
- The user commits directly on `main` themselves; give them the git commands instead of committing for them.

**Next** (in this order)
1. **Finish the user's SEN-008 rule:** replace its contents with the corrected version (or help the user do it), click **Reload rules**, and test it via `POST /api/v1/ingest` (the simulator never generates file-search events). Optionally rename it to `sen-008-file-directory-discovery.yml`. Then the user commits it.
2. **ID clash to resolve:** `rules/README.md` uses **SEN-008** for the lateral movement exercise, but the user's file rule now uses SEN-008. Do the lateral movement exercise as **SEN-009**, and update the guide's example ID to match.
3. Optional: add a **"File search" attack scenario** (T1083) to `sentinela/attacks.py`, so SEN-008 can be tested in a real game.
4. **Security fix** (from the pre-commit check): reject state-changing requests from other origins (CSRF on `/simulation/reset`, `/assets/reset`, `/rules/reload`) and unknown `Host` headers (DNS rebinding). Add tests.
5. **Next big feature: SQLite storage** for events, alerts, attacks and triage, so games survive restarts. Then search/investigation, then a real Windows agent.
- Small/optional: turn off Uvicorn access logs (`access_log=False` in `start.py`) to keep the terminal quiet.

---

## 2026-10-05 — Cleanup, web dashboard, and pivot to a SOC simulator

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
- Added a web GUI: `dashboard/index.html` served by the server at `/`. It shows stat tiles, an alert feed, a live event stream (polls every 2s), and an event simulator with attack presets. Always light theme.
- Server keeps the last 500 events/alerts in memory (cleared on restart). New endpoints: `GET /api/v1/events`, `GET /api/v1/alerts`, `GET /api/v1/stats`, `DELETE /api/v1/events`.
- Added `start.py` / `start.bat` launcher (starts server, opens browser) and a Getting Started section in README. Tests now 21, all passing.
- Explained how SIEMs work (collect, normalize, store, detect, alert, investigate) and their blind spots.
- **Pivot:** refactored the project from a SIEM prototype into the **Sentinela SOC Simulator**:
  - `sentinela/` package replaces `server.py`: `models`, `organization` (virtual company, saved to `data/organization.json`), `activity` (background noise + deliberate false-positive sources), `attacks` (6 simulated attack scenarios), `detection` (7 rules incl. brute-force and logon-after-brute-force correlation), `simulation` (pipeline, alert grouping, triage, scoring), `alerting` (Discord, min severity), `api`.
  - Four pages in `web/`: Overview (big-picture flow, scoreboard, simulation controls, rules), Organization (add/edit/delete assets), SOC (alert queue, details + triage, event stream with search), Attacker (scenario cards, launch, attack log).
  - Removed `server.py`, `dashboard/`, `send_sample_events.py`. `/api/v1/ingest` kept for future real agents.
  - Tests rewritten: 56 passing (`test_detection.py`, `test_simulation.py`, `test_api.py`). Verified live with a full 6-step attack chain: 5 detected, lateral movement missed (intended gap).

**Decisions**
- Keep everything in a single `server.py` until Phase 3 (YAML rules), then split into `agent/` / `server/` / `rules/`.
- Run tests with `python -m pytest`.
- GUI is a plain HTML/JS page served by FastAPI (no extra dependencies or build step), not a desktop app. All event data is rendered with `textContent` because endpoint data is untrusted.
- Storage is in-memory for now; a database (e.g. SQLite) can come later if history must survive restarts.
- Project concept is now a **training simulator** (organization + attacker + SOC). Attacks are high-level and only generate fake log events inside the app; nothing touches real machines.
- SOC views hide ground truth (`origin`, attack links); only the score reveals it, after alerts are closed.
- Lateral movement intentionally has no rule, as a detection-engineering exercise.
- Supersedes the earlier "keep a single `server.py`" decision.

**Next**
- Commit the simulator (work is on branch `phase1-cleanup`, uncommitted since `f06e97b`).
- Write a lateral-movement rule (e.g. admin logon to a server from a host that is not an IT machine).
- Move rules to YAML so they can be edited without code changes.
- Save events/alerts in SQLite so a game survives restarts.
- Later: API key on `/ingest`, `logging` instead of `print`, a real Windows agent.

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
