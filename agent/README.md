# Sentinela Windows Agent

`windows_agent.py` reads **real events from the Windows Security log** of this PC and sends them to Sentinela's `/api/v1/ingest`. They go through the same detection rules as the simulated events, so running `whoami` on your own PC raises SEN-001 in the SOC console.

| Windows event | Meaning | Sentinela event |
|---|---|---|
| **4688** | A process was created | `process_creation` |
| **4624** | An account logged on | `authentication_success` |
| **4625** | An account failed to log on | `authentication_failure` |
| **4720** | A user account was created | `account_created` |

By default the agent and Sentinela run **on the same PC** (it sends to `http://127.0.0.1:8000`); section 5 shows how to collect from other PCs too. It uses only the Python standard library, so the one file can be copied to another PC.

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

## 5. Agents on other machines

Sentinela can also collect events from other Windows PCs in your network. Only sending events is opened to them: the SOC console, the game controls and every other API stay on the Sentinela PC.

**On the Sentinela PC**

1. Make a secret key:

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. Add to `.env` (then restart Sentinela):

   ```
   SENTINELA_HOST=0.0.0.0
   SENTINELA_INGEST_KEY=<the key from step 1>
   ```

   Sentinela refuses to start with `0.0.0.0` and no key.

3. Find this PC's address: run `ipconfig` and look for the **IPv4 Address** of your network adapter (for example `192.168.1.10`).

4. Allow other PCs on your **private** network to reach port 8000 (PowerShell **as Administrator**):

   ```powershell
   New-NetFirewallRule -DisplayName "Sentinela ingest" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -Profile Private -RemoteAddress LocalSubnet
   ```

   Remove it later with `Remove-NetFirewallRule -DisplayName "Sentinela ingest"`.

**On each other PC**

1. Install Python and copy `agent\windows_agent.py` to it (one file is enough).
2. Switch on auditing there (section 1 above) and run `--check`.
3. In a PowerShell **as Administrator**, set the key for this window only, then start the agent with the Sentinela PC's address:

   ```powershell
   $env:SENTINELA_INGEST_KEY = "<the key>"
   python windows_agent.py --server http://192.168.1.10:8000
   ```

   The key is read from the environment on purpose: there is no `--key` option, because process creation events (4688) record full command lines, and the agent would then send its own key to the SIEM.

4. Run `whoami` on that PC: an alert for its host name appears in the SOC console. Add the PC on the **Organization** page so alerts show who normally uses it.

| Message from the agent | Fix |
|---|---|
| `HTTP 401` wrong or missing key | `$env:SENTINELA_INGEST_KEY` must be exactly the key in Sentinela's `.env` |
| `HTTP 403` only accepts events from this PC | Set `SENTINELA_HOST=0.0.0.0` on the Sentinela PC and restart it |
| `HTTP 400` does not answer to this address | Use the Sentinela PC's IPv4 address or its computer name in `--server` |
| `Could not reach Sentinela` | Sentinela is not running, wrong address, or the firewall rule (step 4) is missing |

**Security:** the connection is plain HTTP, so the key and the events can be read by anyone who can watch your network traffic. Use this only on a network you trust, such as your home lab. A real SIEM would add HTTPS (TLS) here.

## Options

| Option | Meaning |
|---|---|
| `--dry-run` | Print the events as JSON, send nothing |
| `--once` | Check one time, then stop |
| `--backfill N` | Also send the last N older events at the start |
| `--include-system` | Also send activity of Windows' own accounts (SYSTEM, `PC$`, services): very noisy |
| `--interval S` | Seconds between checks (default 5) |
| `--server URL` | Sentinela address (default `http://127.0.0.1:8000`) |
| `SENTINELA_INGEST_KEY` (environment) | The key, when Sentinela has one set (always for other machines) |
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
