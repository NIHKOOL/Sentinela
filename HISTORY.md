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

## 2026-10-21 — SEN-007 tuning, SEN-010 password search rule, SQLite storage, investigation

**Done**
- HISTORY.md: marked the SEN-009 work as committed (`9ceb21f`).
- **SEN-007 tuning** (the user's exercise): new `filter_cloud_storage` selection (`dest_ip|cidr: 198.51.100.0/24`), condition `selection and not internal_destination and not filter_cloud_storage`, description updated. First attempt had an invalid condition (`selection internal_destination`, rule skipped by the loader) and the cloud range inside `selection` (inverted logic); both explained and fixed by the user.
- Test: `198.51.100.20` / 100 MB → no alert. Tests: 174 passing.
- Measured one simulated hour (1200 ticks, same seed): SEN-007 false positives 35 → 0; the exfiltration attack to `203.0.113.x` is still detected.
- SOC topics taught: alert fatigue, allow-list filters, and their blind spot (exfiltration to allowed cloud storage, T1567.002).
- Committed by the user: `7130983` (HISTORY), `499dd08` (SEN-007 tuning).
- **SEN-010 Password search in files** (`rules/sen-010-credentials-in-files.yml`, T1552.001, medium): Claude wrote the skeleton, the user filled it in. `search_programs` (grep, egrep, fgrep, zgrep, rg) and `secret_words` (`password`, `secret`). Review fixed: `egrap` typo, `ri` (a grep option, not a program), and `passwd` removed (matched `grep alice /etc/passwd`, an account lookup; the file holds no passwords).
- Tests: shipped-rule ID lists use `f"SEN-{n:03d}"` (the old `SEN-00{n}` gives `SEN-0010`); SEN-010 must-catch/must-ignore cases; Linux File search is now detected by SEN-008 + SEN-010. Tests: 181 passing.
- README (rule table, blind spots, false-positive list, skills, roadmap) and `rules/README.md` (SEN-007 / SEN-010 ideas marked solved) updated. Committed by the user: `b948b52`.
- SEN-007 polish by the user: obsolete cloud-storage false positive removed, blind-spot comment (T1567.002) added.
- **SQLite storage** (`sentinela/storage.py`, stdlib `sqlite3`, file `data/sentinela.db`, WAL mode; in memory when no data dir, as in tests). Tables: `attacks`, `events` (event JSON in `data`; `origin` and `attack_id` in their own columns), `alerts` (with `group_key` for grouping), `alert_events` (many-to-many). `Simulation` now reads and writes through the `Store`; one transaction per ingest; Discord/print happen after the commit. `create_app` builds the store, `lifespan` closes it.
- Fixed a ground-truth leak found on the way: the event search also searched the hidden `origin` field, so searching "attack" listed only attacker events. `origin` is now outside the searchable data.
- Removed the 5000-event memory cap (the database keeps every event until **Reset**). Correlation memory is not saved: it starts empty after a restart.
- New `tests/test_storage.py` (5 tests: game survives a restart, ids continue, grouping joins a saved alert, reset clears the file, search hides ground truth). Tests: 186 passing. Verified live on port 8766: attack + restart → events, alert and attack still there.
- README (feature note, troubleshooting "fresh game", project structure, roadmap) and `.gitignore` comment updated. Committed by the user: `ada7fcb` (SEN-007 polish), `9f131c6` (SQLite storage).
- Taught SQL on `data/sentinela.db` (VS Code SQLite extensions, `json_extract`, GROUP BY, the WAL caveat); queries for host events, failed logons per IP (with `users_tried` to tell brute force from spraying) and the open HIGH/CRITICAL queue.
- **Search / investigation** (SOC page):
  - `GET /api/v1/events` new filters: `user` (ignores case), `ip` (source or destination), `event_type`, `since` / `until` (no timezone = UTC), `oldest_first`; all filters must match. SQL in `Store.list_events` via `json_extract`; timestamps compared as fixed-format UTC text (`_utc_text`).
  - SOC page: filter bar (host, event type, user, IP, text, Clear); hosts, users and IPs in the event table and alert details are **pivots** (click = show all events for that value, other filters cleared); **Timeline ±10 min** button on an alert (host + time window, oldest first, the alert's own events highlighted, removable chip).
  - Tests: 11 API filter tests. Tests: 197 passing. Verified in headless Chrome via DevTools Protocol (15 click checks: timeline, highlight, pivots, type filter, Clear, filters survive polling).
- Mistake: my live tests loaded the user's `.env`, so a few simulated alerts were posted to their Discord. Live tests now set `DISCORD_WEBHOOK_URL=""`.

**Decisions**
- Cloud storage is filtered by destination range only (no size or port limit): the user's tuning choice.
- SEN-010 is credential access (T1552.001), not discovery: it reads file contents for secrets.
- SQLite is the single source of truth (no in-memory copy), to prepare for search/investigation queries. Events are not pruned for now.

**Next** (in this order)
1. User commits the investigation work.
2. Optional investigation extras: "Top" summary for a host/user (most-run programs, failed-logon IPs), keep the pivot filters in the URL so an investigation can be bookmarked.
3. **Detection exercise for the user:** password spraying with `value_count` (needs a new attack scenario).
4. Real Windows agent that sends Event Log data to `/api/v1/ingest`.
- Known issue (older than this session): on phone width (~420 px) the whole page is wider than the screen (top bar chips and stat cards overflow).
- Later: maybe prune old events (e.g. keep the last N days) if the database grows too big.

---

## 2026-10-12 — SEN-008 hardened, File search attack, CSRF / DNS rebinding fix, skills section, SEN-009

**Done**
- Read the whole project. The committed SEN-008 (`5bb02a8`) had broken 2 tests that hard-coded SEN-001..007; fixed, and added SEN-008 tests (7 must-catch, 3 must-ignore).
- Hardened SEN-008 against evasion: `dir /s` and `Get-ChildItem -Recurse` now use `contains|all` (catches `dir /b /s`, extra arguments in between), added `find.exe` (Windows). `filter_it` kept, with its risk (stolen it-admin account) noted in the rule.
- `rules/README.md` lateral movement exercise renamed **SEN-009** (no clash with SEN-008); `tests/test_api.py` matches.
- New attack scenario **File search** (T1083, `attacks.py`): Windows `dir /s`, `findstr /si password`, `Get-ChildItem -Recurse -Include *.kdbx,*.pfx`; Linux `find` + `grep` (grep is not detected: a deliberate small gap). Added to the attack chain on the Attacker page.
- New background activity **developer_search** (weight 2, Engineering workstation): `where python`, `findstr /s TODO`, `Get-ChildItem -Recurse` → SEN-008 false positives to triage.
- Measured one simulated hour: SEN-008 57 matching events → 2 alerts (grouping); SEN-007 is the noisiest (22 HIGH false positives/hour).
- **Security fix** (`api.py`): state-changing requests with a foreign `Origin` / `Sec-Fetch-Site: cross-site` get 403 (CSRF); `TrustedHostMiddleware` allows only `127.0.0.1` / `localhost` (DNS rebinding), configurable with `SENTINELA_ALLOWED_HOSTS`. Requests without `Origin` (agents, curl) still work. Tests use `base_url=http://127.0.0.1:8000`.
- `start.py`: Uvicorn access log off, so the terminal shows alerts only.
- README: File search in features/rules table, security note, troubleshooting row, roadmap, and a new **Skills Demonstrated** section (SOC analysis, detection engineering, secure development) as portfolio evidence.
- Verified live (port 8765): File search on DB01 → SEN-008 (3 events, 1 alert); forged cross-site reset → 403; rebinding Host → 400; agent ingest → 200. Tests: 163 passing.
- Committed by the user: `1a5caca` (everything above).
- **SEN-009 lateral movement** (the user's exercise, `rules/sen-009-lateral-movement.yml`). Review found: `condition: selective` typo (rule silently skipped by the loader), file misnamed `sen-009-grep-ri-password.yml`, SEN-008 accidentally renamed to `... copy.yml`, title/description typos, date `2026-12-10`. All fixed at the user's request; blind spots (attacker on WS-IT01, `it-admin` not covered) documented as comments in the rule. Verified: 3 of 4 lateral movement sources detected (WS-IT01 missed by design), 0 false positives in 1200 background ticks.
- Tests: SEN-009 must-catch/must-ignore cases; `test_lateral_movement_is_a_detection_gap` replaced by "is detected" + "WS-IT01 is a blind spot". 173 passing. README (rule table, gaps, skills, roadmap) and `rules/README.md` (exercise marked solved, SEN-010 grep and SEN-007 tuning ideas) updated.
- Committed by the user: `9ceb21f` (SEN-009 work).
- SOC topics taught: process creation telemetry (4688 / Sysmon 1) and the command line as evidence; Windows event IDs 4624/4625/4720; T1083 and what attackers search for (kdbx, pfx, configs); TP vs FP by context; evasion of exact string matches; tuning trade-offs; alert grouping and alert fatigue.

**Decisions**
- SEN-008 keeps the `it-admin` filter; the blind spot is documented instead of removed (the user's tuning choice).
- Same-origin check compares `Origin` with the `Host` header, so both `127.0.0.1:8000` and `localhost:8000` work. GET requests are not checked (other sites cannot read responses without CORS headers).

**Next** (in this order)
1. **Tuning exercise for the user:** cut SEN-007's false positives (e.g. a filter for the cloud storage range `198.51.100.0/24`), then check that real exfiltration to `203.0.113.x` is still caught.
2. **Detection exercises for the user:** SEN-010 for `grep -ri password` on Linux (closes the File search gap); password spraying with `value_count`.
3. **SQLite storage** for events, alerts, attacks and triage, so games survive restarts. Then search/investigation (timeline per host/user), then a real Windows agent.

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
