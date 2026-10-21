"""Sentinela Windows agent: reads the Windows Security event log and sends the events to Sentinela.

Run it in a terminal opened "as Administrator" (the Security log needs admin rights),
on the same machine as Sentinela:

    python agent/windows_agent.py --check      # does Windows record what we need?
    python agent/windows_agent.py --dry-run    # show the events, send nothing
    python agent/windows_agent.py              # send new events to Sentinela, until Ctrl+C

Collected events (Windows Security log -> Sentinela event type):

    4688 a process was created           -> process_creation
    4624 an account logged on            -> authentication_success
    4625 an account failed to log on     -> authentication_failure
    4720 a user account was created      -> account_created

Only the Python standard library is used, so this file also runs on its own.
"""
import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

EVENT_TYPES = {
    4688: "process_creation",
    4624: "authentication_success",
    4625: "authentication_failure",
    4720: "account_created",
}
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Windows' own accounts. Their activity is constant background noise, so it is skipped unless asked for.
SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon"}
SYSTEM_PREFIXES = ("dwm-", "umfd-")       # desktop window manager and font driver sessions
# Logon types a person causes: interactive, network, unlock, network cleartext, remote desktop, cached.
# Left out: 4 batch, 5 service, 9 new credentials (runas /netonly), 0 system.
PERSON_LOGON_TYPES = {"2", "3", "7", "8", "10", "11"}

# Audit subcategories, by GUID because the names are translated on non-English Windows
AUDIT_SUBCATEGORIES = {
    "Process Creation": "{0CCE922B-69AE-11D9-BED3-505054503030}",
    "Logon": "{0CCE9215-69AE-11D9-BED3-505054503030}",
    "User Account Management": "{0CCE9235-69AE-11D9-BED3-505054503030}",
}
CMDLINE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
CMDLINE_VALUE = "ProcessCreationIncludeCmdLine_Enabled"

DEFAULT_SERVER = "http://127.0.0.1:8000"
DEFAULT_STATE = Path(__file__).resolve().parent.parent / "data" / "agent-state.json"
BATCH = 200


# --- Reading the event log ---

class EventLogError(Exception):
    pass


def wevtutil(*args: str) -> str:
    """Run wevtutil (built into Windows) and return its output."""
    try:
        result = subprocess.run(["wevtutil", *args], capture_output=True, text=True, errors="replace")
    except FileNotFoundError:
        raise EventLogError("wevtutil was not found. The agent only runs on Windows.")
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        if result.returncode == 5 or "denied" in message.lower():
            message = "Access is denied. The Security log needs admin rights: open the terminal with 'Run as administrator'."
        raise EventLogError(message)
    return result.stdout


def security_query(after_record_id: Optional[int] = None) -> str:
    """XPath filter for the collected event ids, optionally only events newer than a record id."""
    ids = " or ".join(f"EventID={event_id}" for event_id in EVENT_TYPES)
    newer = f" and EventRecordID>{after_record_id}" if after_record_id is not None else ""
    return f"*[System[({ids}){newer}]]"


def read_new_events(after_record_id: int, count: int = BATCH) -> list[dict]:
    """The next `count` collected events after a record id, oldest first."""
    xml = wevtutil("qe", "Security", f"/q:{security_query(after_record_id)}", f"/c:{count}", "/f:xml", "/e:Events")
    return parse_events(xml)


def read_latest_events(count: int) -> list[dict]:
    """The last `count` collected events, oldest first."""
    xml = wevtutil("qe", "Security", f"/q:{security_query()}", f"/c:{count}", "/rd:true", "/f:xml", "/e:Events")
    return list(reversed(parse_events(xml)))


def latest_record_id() -> int:
    """Record id of the newest event in the Security log (of any kind), or 0 if it is empty."""
    events = parse_events(wevtutil("qe", "Security", "/c:1", "/rd:true", "/f:xml", "/e:Events"))
    return events[0]["record_id"] if events else 0


def parse_events(xml: str) -> list[dict]:
    """Turn wevtutil's XML (wrapped in <Events>) into simple dicts."""
    events = []
    for node in ET.fromstring(xml).findall("e:Event", NS):
        system = node.find("e:System", NS)
        data = {item.get("Name"): (item.text or "") for item in node.findall("e:EventData/e:Data", NS)}
        events.append({
            "event_id": int(system.findtext("e:EventID", "0", NS)),
            "record_id": int(system.findtext("e:EventRecordID", "0", NS)),
            "time": system.find("e:TimeCreated", NS).get("SystemTime"),
            "computer": system.findtext("e:Computer", "", NS),
            "data": data,
        })
    return events


# --- Mapping to Sentinela's event schema ---

def _value(text: Optional[str]) -> Optional[str]:
    """Windows writes '-' for an empty field."""
    return text if text and text != "-" else None


def is_system_account(name: Optional[str]) -> bool:
    if not name:
        return True
    lowered = name.lower()
    return lowered.endswith("$") or lowered in SYSTEM_ACCOUNTS or lowered.startswith(SYSTEM_PREFIXES)


def _timestamp(system_time: str) -> str:
    # Windows gives 7 decimals ('...00.1234567Z'); Python and Sentinela read up to 6
    head, dot, rest = system_time.rstrip("Z").partition(".")
    return f"{head}.{rest[:6]}Z" if dot else f"{head}Z"


def to_telemetry(raw: dict, include_system: bool = False) -> Optional[dict]:
    """A Sentinela event for one Windows event, or None if it is skipped as noise."""
    kind = EVENT_TYPES.get(raw["event_id"])
    if kind is None:
        return None
    data = raw["data"]
    event = {"timestamp": _timestamp(raw["time"]), "hostname": raw["computer"].split(".")[0], "event_type": kind}

    if kind == "process_creation":
        # TargetUserName is the account the new process runs as (Windows 10+); older logs only have the subject
        user = _value(data.get("TargetUserName")) or _value(data.get("SubjectUserName"))
        event.update(process_name=_value(data.get("NewProcessName")), command_line=_value(data.get("CommandLine")))
    elif kind in ("authentication_success", "authentication_failure"):
        if data.get("LogonType") not in PERSON_LOGON_TYPES:
            return None
        user = _value(data.get("TargetUserName"))
        event.update(source_ip=_value(data.get("IpAddress")))
    else:  # account_created: the subject created the target
        user = _value(data.get("SubjectUserName"))
        event.update(target_user=_value(data.get("TargetUserName")))

    if is_system_account(user):
        if not include_system:
            return None
        user = "SYSTEM"
    event["user"] = user
    return {key: value for key, value in event.items() if value is not None}


# --- Sending ---

def send(server: str, event: dict) -> dict:
    request = urllib.request.Request(f"{server}/api/v1/ingest", data=json.dumps(event).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


# --- Remembering where we stopped ---

def load_state(path: Path) -> Optional[int]:
    try:
        return int(json.loads(path.read_text(encoding="utf-8"))["last_record_id"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_state(path: Path, record_id: int):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"last_record_id": record_id}), encoding="utf-8")


# --- Commands ---

def describe(event: dict) -> str:
    detail = event.get("command_line") or event.get("process_name") or event.get("source_ip") or event.get("target_user") or ""
    return f"{event['timestamp'][11:19]} {event['hostname']} {event['event_type']:<23} {event['user']:<15} {detail}"


def handle(events: list[dict], args, sent_to: Optional[str]) -> Optional[int]:
    """Send (or print) a batch. Returns the record id of the last event handled; stops at the first send error."""
    handled = None
    for raw in events:
        event = to_telemetry(raw, args.include_system)
        if event is not None:
            if sent_to is None:
                print(json.dumps(event))
            else:
                try:
                    result = send(sent_to, event)
                except (urllib.error.URLError, OSError) as e:
                    print(f"[-] Could not reach Sentinela at {sent_to} ({e}). Will retry.")
                    return handled
                alert = f"  -> ALERT {result['alert_ids']}" if result.get("alert_triggered") else ""
                print(f"[+] {describe(event)}{alert}")
        handled = raw["record_id"]
    return handled


def run(args) -> int:
    sent_to = None if args.dry_run else args.server.rstrip("/")
    state_path = Path(args.state)
    last = load_state(state_path)

    if args.backfill:
        events = read_latest_events(args.backfill)
        if last is not None:
            events = [e for e in events if e["record_id"] > last]
        print(f"[*] Sending the last {len(events)} collected events first")
        last = handle(events, args, sent_to) or last
    if last is None:
        last = latest_record_id()  # first run: start with events from now on, not the whole history
        print("[*] First run: collecting new events from now on (use --backfill N to also send older ones)")
    if not args.dry_run:
        save_state(state_path, last)

    print(f"[*] Watching the Security log{'' if sent_to else ' (dry run: printing only)'}. Stop with Ctrl+C.")
    while True:
        events = read_new_events(last)
        handled = handle(events, args, sent_to)
        if handled is not None:
            last = handled
            if not args.dry_run:
                save_state(state_path, last)
        if args.once:
            return 0
        if len(events) < BATCH or handled != events[-1]["record_id"]:
            time.sleep(args.interval)


def check() -> int:
    """Show whether Windows records the events the agent needs."""
    ok = True
    for name, guid in AUDIT_SUBCATEGORIES.items():
        result = subprocess.run(["auditpol", "/get", f"/subcategory:{guid}"], capture_output=True, text=True, errors="replace")
        if result.returncode != 0:
            print(f"[-] {name}: cannot read the audit policy ({(result.stderr or result.stdout).strip()})")
            print("    Run the terminal as Administrator.")
            return 1
        line = next((l.strip() for l in result.stdout.splitlines() if guid.lower() in l.lower() or name in l), "")
        print(f"[*] {name}: {line or result.stdout.strip().splitlines()[-1]}")

    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CMDLINE_KEY) as key:
            enabled = winreg.QueryValueEx(key, CMDLINE_VALUE)[0] == 1
    except (ImportError, OSError):
        enabled = False
    print(f"[{'*' if enabled else '-'}] Command line in process events: {'on' if enabled else 'OFF'}")
    ok = ok and enabled

    try:
        print(f"[*] Security log readable, newest record id {latest_record_id()}")
    except EventLogError as e:
        print(f"[-] Security log: {e}")
        ok = False
    print("See agent/README.md to switch on anything that is missing.")
    return 0 if ok else 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Send Windows Security log events to Sentinela.")
    parser.add_argument("--server", default=DEFAULT_SERVER, help=f"Sentinela address (default {DEFAULT_SERVER})")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between checks (default 5)")
    parser.add_argument("--backfill", type=int, default=0, metavar="N", help="also send the last N older events at start")
    parser.add_argument("--include-system", action="store_true", help="also send activity of Windows' own accounts (noisy)")
    parser.add_argument("--state", default=str(DEFAULT_STATE), help="file that remembers the last event sent")
    parser.add_argument("--dry-run", action="store_true", help="print the events instead of sending them")
    parser.add_argument("--once", action="store_true", help="check one time, then stop")
    parser.add_argument("--check", action="store_true", help="show whether auditing is switched on, then stop")
    args = parser.parse_args(argv)

    try:
        return check() if args.check else run(args)
    except EventLogError as e:
        print(f"[-] {e}")
        return 1
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
