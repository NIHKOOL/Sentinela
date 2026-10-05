"""Attacker playbook: high-level, simulated attack steps.

Each scenario only creates fake log events inside the simulation (the traces
an attack like it would leave in real logs). Nothing here runs on or touches
a real computer.
"""
import random
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Optional

from .models import Asset, TelemetryEvent, utc_now
from .organization import is_linux

ATTACKER_IPS = [f"203.0.113.{n}" for n in range(10, 250)]  # documentation range, stands in for "the internet"
BACKDOOR_NAMES = ["support", "svc-update", "helpdesk2", "backup-admin"]


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    tactic: str
    mitre: str
    description: str
    needs_source: bool = False
    supports_success: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


SCENARIOS = {s.id: s for s in [
    Scenario("password_guessing", "Password guessing", "Credential Access", "T1110",
             "Try many passwords against the admin account of the target, from the internet.",
             supports_success=True),
    Scenario("discovery", "Discovery", "Discovery", "T1033 / T1087",
             "After getting in, look around: which user am I, which accounts and groups exist."),
    Scenario("credential_theft", "Credential theft", "Credential Access", "T1003",
             "Run a (simulated) tool that steals saved passwords from the target's memory."),
    Scenario("backdoor_account", "Create backdoor account", "Persistence", "T1136",
             "Create a new user account on the target so you can come back later."),
    Scenario("lateral_movement", "Lateral movement", "Lateral Movement", "T1021",
             "Use stolen admin credentials to log in from one machine you control to the target.",
             needs_source=True),
    Scenario("exfiltration", "Data exfiltration", "Exfiltration", "T1048",
             "Upload a large amount of company data from the target to an outside server."),
]}


def generate(scenario_id: str, target: Asset, source: Optional[Asset], succeed: bool,
             rng: random.Random, now: Optional[datetime] = None) -> list[TelemetryEvent]:
    """Create the simulated events for one attack step, oldest first."""
    return BUILDERS[scenario_id](target, source, succeed, rng, now or utc_now())


def _admin_user(target: Asset) -> str:
    return "root" if is_linux(target) else "administrator"


def _compromised_user(target: Asset) -> str:
    return target.users[0] if target.users else _admin_user(target)


# --- Builders: one per scenario ---

def _password_guessing(target, source, succeed, rng, now):
    attacker_ip = rng.choice(ATTACKER_IPS)
    user = _admin_user(target)
    attempts = rng.randint(8, 15)
    events = [
        TelemetryEvent(timestamp=now - timedelta(seconds=2 * (attempts - i)), hostname=target.hostname,
                       event_type="authentication_failure", user=user, source_ip=attacker_ip)
        for i in range(attempts)
    ]
    if succeed:
        events.append(TelemetryEvent(timestamp=now, hostname=target.hostname,
                                     event_type="authentication_success", user=user, source_ip=attacker_ip))
    return events


def _discovery(target, source, succeed, rng, now):
    user = _compromised_user(target)
    if is_linux(target):
        steps = [("/usr/bin/whoami", "whoami"), ("/usr/bin/id", "id")]
    else:
        steps = [("C:\\Windows\\System32\\whoami.exe", "whoami"),
                 ("C:\\Windows\\System32\\net.exe", "net user"),
                 ("C:\\Windows\\System32\\net.exe", "net localgroup administrators")]
    return [
        TelemetryEvent(timestamp=now - timedelta(seconds=3 * (len(steps) - i)), hostname=target.hostname,
                       event_type="process_creation", user=user, process_name=process, command_line=command)
        for i, (process, command) in enumerate(steps)
    ]


def _credential_theft(target, source, succeed, rng, now):
    process = "/tmp/credential_dumper" if is_linux(target) else "C:\\Users\\Public\\credential_dumper.exe"
    return [TelemetryEvent(timestamp=now, hostname=target.hostname, event_type="process_creation",
                           user=_compromised_user(target), process_name=process,
                           command_line="credential_dumper (simulated)")]


def _backdoor_account(target, source, succeed, rng, now):
    return [TelemetryEvent(timestamp=now, hostname=target.hostname, event_type="account_created",
                           user=_admin_user(target), target_user=rng.choice(BACKDOOR_NAMES))]


def _lateral_movement(target, source, succeed, rng, now):
    # A normal-looking admin logon, just from an unusual machine. No default rule catches this.
    return [TelemetryEvent(timestamp=now, hostname=target.hostname, event_type="authentication_success",
                           user=_admin_user(target), source_ip=str(source.ip))]


def _exfiltration(target, source, succeed, rng, now):
    return [TelemetryEvent(timestamp=now, hostname=target.hostname, event_type="network_connection",
                           user=_compromised_user(target), dest_ip=rng.choice(ATTACKER_IPS), dest_port=443,
                           bytes_out=rng.randint(200_000_000, 900_000_000))]


BUILDERS = {
    "password_guessing": _password_guessing,
    "discovery": _discovery,
    "credential_theft": _credential_theft,
    "backdoor_account": _backdoor_account,
    "lateral_movement": _lateral_movement,
    "exfiltration": _exfiltration,
}
