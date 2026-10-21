# Sentinela Windows Agent

`windows_agent.py` reads **real events from the Windows Security log** of this PC and sends them to Sentinela's `/api/v1/ingest`. They go through the same detection rules as the simulated events, so running `whoami` on your own PC raises SEN-001 in the SOC console.

| Windows event | Meaning | Sentinela event |
|---|---|---|
| **4688** | A process was created | `process_creation` |
| **4624** | An account logged on | `authentication_success` |
| **4625** | An account failed to log on | `authentication_failure` |
| **4720** | A user account was created | `account_created` |

The agent and Sentinela run **on the same PC** (it sends to `http://127.0.0.1:8000`). It uses only the Python standard library.

---

## 1. Switch on Windows auditing (once)

Windows does not record all of these events by default. Open **PowerShell as Administrator** (Start menu → type `PowerShell` → right-click → **Run as administrator**) and run:

```powershell
# 4688 process creation
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable
# 4624 / 4625 logons (success and failure)
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
# 4720 account created
auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable
# Put the full command line into 4688 events (most rules need it)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

The long `{...}` codes are the audit categories' fixed IDs. They work on Windows in any language, while names such as "Process Creation" are translated.

## 2. Check

In the same **Administrator** terminal, from the Sentinela folder:

```powershell
python agent\windows_agent.py --check
```

All lines should show auditing switched on and `Command line in process events: on`.

## 3. Try it without sending

```powershell
python agent\windows_agent.py --dry-run
```

Open another terminal and run `whoami`. A `process_creation` line for `whoami.exe` appears within 5 seconds. Stop with **Ctrl+C**.

## 4. Send to Sentinela

1. Start Sentinela as usual (`python start.py`).
2. Optional: on the **Organization** page, add this PC (its name is shown by `hostname`) so alerts show its criticality and known users.
3. Optional: pause the background simulation on the Overview page, so you only see your own events.
4. In the **Administrator** terminal:

```powershell
python agent\windows_agent.py
```

Things to try (normal user terminal):

| Do this | Expected |
|---|---|
| `whoami` or `net user` | SEN-001 Discovery commands |
| `dir C:\Users /s` (stop it with Ctrl+C) | SEN-008 File and directory discovery |
| `runas /user:administrator cmd` with a wrong password | 4625 event, SEN-002 Logon failure for privileged account |
| The same 5 times within 60 seconds | Maybe SEN-003 Brute force: it counts per source IP, and Windows does not always record one for a local logon (a detection gap worth looking at) |

## Options

| Option | Meaning |
|---|---|
| `--dry-run` | Print the events as JSON, send nothing |
| `--once` | Check one time, then stop |
| `--backfill N` | Also send the last N older events at the start |
| `--include-system` | Also send activity of Windows' own accounts (SYSTEM, `PC$`, services): very noisy |
| `--interval S` | Seconds between checks (default 5) |
| `--server URL` | Sentinela address (default `http://127.0.0.1:8000`) |
| `--state FILE` | Where the agent remembers the last event sent (default `data/agent-state.json`) |

The first run starts with **new** events only. After that the agent continues where it stopped, also after a restart. If Sentinela is not running, the agent keeps the events and retries.

## Good to know

* **Admin rights:** only Administrators can read the Security log. Without them you get `Access is denied`.
* **Privacy:** command lines can contain secrets (for example a password typed as an argument). Real events are stored in `data/sentinela.db` on this PC only; that folder is not committed to git. **Reset** in the app deletes them.
* **Noise filter:** logons by services, batch jobs and Windows' own accounts are skipped. A person's logon (interactive, network, unlock, remote desktop) is kept.
* **Score:** real events are not attacks from the game, so an alert on them counts as a **false positive** on the scoreboard.

## Switch auditing off again

```powershell
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:disable
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /f
```

Logon and account-management auditing are usually on in Windows by default, so leave them unless you switched them on yourself.
