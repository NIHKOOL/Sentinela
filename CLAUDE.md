# Sentinela

Sentinela is a SOC training simulator: a virtual organization, simulated attacker steps, and a SOC console on top of a small SIEM (FastAPI + plain HTML/JS). See `README.md` for the overview, architecture, and roadmap.

- Code lives in the `sentinela/` package; pages in `web/`. Start with `python start.py`; test with `python -m pytest`.
- Attack scenarios must stay high-level and simulated: they only generate fake log events inside the app.
- Render event data in the browser with `textContent` (the `S.el` helper), never `innerHTML`.
- SOC-facing API responses must not expose ground truth (event `origin`, attack links).
- Detection rules live in `rules/*.yml` (Sigma-style; engine in `sentinela/rules.py`, format guide in `rules/README.md`). Load YAML with `yaml.safe_load` only. Changing a shipped rule's behaviour needs `tests/test_detection.py` updated too.

## Session history

`HISTORY.md` is the running log of work sessions. At the end of every session that changes the project, add a new entry at the top of the log (below the `---` after the template) using the template in that file: date, short title, **Done**, **Decisions** (if any), and **Next**. Keep entries brief and reference commit hashes where relevant. If a session continues on the same day as the latest entry, update that entry instead of adding a duplicate.
