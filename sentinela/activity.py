"""Normal background activity: the everyday "noise" a real SOC has to look through.

Most of it is harmless and triggers nothing. A few kinds (an admin running
whoami, IT creating an account, a big upload to cloud storage) trigger rules
on purpose. Those are false positives, and the SOC has to recognize them.
"""
import random
from datetime import datetime, timedelta
from typing import Optional

from .models import Asset, TelemetryEvent, utc_now
from .organization import is_linux

WORKSTATION_APPS = ["chrome.exe", "outlook.exe", "excel.exe", "winword.exe", "teams.exe", "explorer.exe", "onedrive.exe"]
SERVER_APPS = {
    "domain_controller": ["lsass.exe", "dns.exe", "dfsrs.exe", "svchost.exe"],
    "web_server": ["nginx", "sshd", "php-fpm", "cron"],
    "database": ["sqlservr.exe", "sqlagent.exe", "svchost.exe"],
    "server": ["svchost.exe", "backup_agent.exe", "spoolsv.exe"],
}
CLOUD_STORAGE_IPS = [f"198.51.100.{n}" for n in range(10, 60)]  # documentation range, stands in for "the internet"
NEW_HIRES = ["j.smith", "m.garcia", "a.chen", "k.okafor", "s.novak", "p.silva"]

# (kind, weight). Weights are relative: most activity is ordinary logons and programs.
KINDS = [
    ("logon", 25),
    ("process", 45),
    ("typo", 8),
    ("internal_transfer", 10),
    ("admin_discovery", 2),
    ("admin_account_created", 1),
    ("cloud_upload", 1),
]


def generate(assets: list[Asset], rng: random.Random, now: Optional[datetime] = None) -> list[TelemetryEvent]:
    """Create a few random, mostly normal events across the organization."""
    if not assets:
        return []
    now = now or utc_now()
    kinds, weights = zip(*KINDS)
    events = []
    for i in range(rng.randint(1, 3)):
        kind = rng.choices(kinds, weights)[0]
        event = BUILDERS[kind](assets, rng, now - timedelta(milliseconds=300 * i))
        if event:
            events.append(event)
    return events


# --- Helpers ---

def _workstations(assets):
    return [a for a in assets if a.role == "workstation"]


def _servers(assets):
    return [a for a in assets if a.role != "workstation"]


def _regular_user(asset: Asset, rng) -> str:
    regular = [u for u in asset.users if u.lower() not in {"administrator", "root"}]
    return rng.choice(regular or asset.users or ["svc-account"])


def _client_ip(asset: Asset, assets, rng) -> str:
    """Where a logon to `asset` comes from: itself for workstations, a workstation for servers."""
    if asset.role == "workstation":
        return str(asset.ip)
    workstations = _workstations(assets)
    return str(rng.choice(workstations).ip) if workstations else "10.0.1.250"


# --- Builders: one per kind of activity ---

def _logon(assets, rng, now):
    asset = rng.choice(assets)
    return TelemetryEvent(timestamp=now, hostname=asset.hostname, event_type="authentication_success",
                          user=_regular_user(asset, rng), source_ip=_client_ip(asset, assets, rng))


def _process(assets, rng, now):
    asset = rng.choice(assets)
    if asset.role == "workstation":
        process, user = rng.choice(WORKSTATION_APPS), _regular_user(asset, rng)
    else:
        process, user = rng.choice(SERVER_APPS.get(asset.role, SERVER_APPS["server"])), "SYSTEM"
    return TelemetryEvent(timestamp=now, hostname=asset.hostname, event_type="process_creation",
                          user=user, process_name=process, command_line=process)


def _typo(assets, rng, now):
    # One mistyped password: normal, should not look like an attack
    asset = rng.choice(assets)
    return TelemetryEvent(timestamp=now, hostname=asset.hostname, event_type="authentication_failure",
                          user=_regular_user(asset, rng), source_ip=_client_ip(asset, assets, rng))


def _internal_transfer(assets, rng, now):
    # Backups and file copies between internal machines: big, but not to the internet
    servers = _servers(assets)
    if len(assets) < 2 or not servers:
        return None
    destination = rng.choice(servers)
    source = rng.choice([a for a in assets if a.id != destination.id])
    return TelemetryEvent(timestamp=now, hostname=source.hostname, event_type="network_connection",
                          user="SYSTEM", dest_ip=str(destination.ip), dest_port=445,
                          bytes_out=rng.randint(1_000_000, 400_000_000))


def _admin_discovery(assets, rng, now):
    # IT admin checking a server. Triggers SEN-001: a false positive.
    servers = [a for a in _servers(assets) if not is_linux(a)]
    if not servers:
        return None
    asset = rng.choice(servers)
    process = rng.choice(["whoami.exe", "systeminfo.exe"])
    return TelemetryEvent(timestamp=now, hostname=asset.hostname, event_type="process_creation",
                          user="it-admin", process_name=process, command_line=process.removesuffix(".exe"))


def _admin_account_created(assets, rng, now):
    # IT onboarding a new employee. Triggers SEN-006: a false positive.
    controllers = [a for a in assets if a.role == "domain_controller"]
    if not controllers:
        return None
    return TelemetryEvent(timestamp=now, hostname=rng.choice(controllers).hostname, event_type="account_created",
                          user="it-admin", target_user=rng.choice(NEW_HIRES))


def _cloud_upload(assets, rng, now):
    # An employee uploading a big presentation to cloud storage. Triggers SEN-007: a false positive.
    workstations = _workstations(assets)
    if not workstations:
        return None
    asset = rng.choice(workstations)
    return TelemetryEvent(timestamp=now, hostname=asset.hostname, event_type="network_connection",
                          user=_regular_user(asset, rng), dest_ip=rng.choice(CLOUD_STORAGE_IPS), dest_port=443,
                          bytes_out=rng.randint(55_000_000, 150_000_000))


BUILDERS = {
    "logon": _logon,
    "process": _process,
    "typo": _typo,
    "internal_transfer": _internal_transfer,
    "admin_discovery": _admin_discovery,
    "admin_account_created": _admin_account_created,
    "cloud_upload": _cloud_upload,
}
