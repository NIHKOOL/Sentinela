"""Detection engine: rules that turn events into alerts.

Single-event rules look at one event. Correlation rules (SEN-003, SEN-004)
remember earlier events and look for a pattern over time.
"""
import ntpath
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network

from .models import TelemetryEvent

RULES = {
    "SEN-001": {
        "name": "Discovery command executed",
        "severity": "MEDIUM",
        "mitre": "T1033 / T1087",
        "description": "A built-in tool attackers use to learn about a system (whoami, net, nltest, systeminfo) was run.",
    },
    "SEN-002": {
        "name": "Logon failure for privileged account",
        "severity": "LOW",
        "mitre": "T1110",
        "description": "A failed logon for administrator, admin or root.",
    },
    "SEN-003": {
        "name": "Brute force: many failed logons",
        "severity": "HIGH",
        "mitre": "T1110",
        "description": "5 or more failed logons from the same source to the same host within 60 seconds.",
    },
    "SEN-004": {
        "name": "Successful logon after brute force",
        "severity": "CRITICAL",
        "mitre": "T1110 / T1078",
        "description": "A successful logon from a source that triggered a brute force alert in the last 10 minutes.",
    },
    "SEN-005": {
        "name": "Known credential theft tool",
        "severity": "CRITICAL",
        "mitre": "T1003",
        "description": "A process name matches a known password-stealing tool.",
    },
    "SEN-006": {
        "name": "New user account created",
        "severity": "MEDIUM",
        "mitre": "T1136",
        "description": "A new user account was created. Attackers do this to keep access.",
    },
    "SEN-007": {
        "name": "Large upload to the internet",
        "severity": "HIGH",
        "mitre": "T1048",
        "description": "50 MB or more sent from an internal host to an external IP in one connection.",
    },
}

DISCOVERY_TOOLS = {"whoami.exe", "whoami", "net.exe", "net1.exe", "nltest.exe", "systeminfo.exe"}
CREDENTIAL_TOOLS = {"mimikatz.exe", "credential_dumper.exe", "credential_dumper"}
PRIVILEGED_USERS = {"administrator", "admin", "root"}
LARGE_UPLOAD_BYTES = 50_000_000
INTERNAL_NETWORKS = [ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]


@dataclass
class Match:
    rule_id: str
    details: str
    event_ids: list[int]


def normalize_process_name(process_name: str) -> str:
    # "C:\Windows\System32\WHOAMI.EXE" -> "whoami.exe" (ntpath handles both \ and /)
    return ntpath.basename(process_name).lower()


def is_external(ip: str) -> bool:
    try:
        address = ip_address(ip)
    except ValueError:
        return False
    return not any(address in network for network in INTERNAL_NETWORKS)


class Detector:
    def __init__(self, threshold: int = 5, window: timedelta = timedelta(seconds=60),
                 follow_up: timedelta = timedelta(minutes=10)):
        self.threshold = threshold
        self.window = window
        self.follow_up = follow_up
        self.reset()

    def reset(self):
        # (hostname, source_ip) -> recent failures as (timestamp, event_id)
        self._failures: dict[tuple[str, str], deque[tuple[datetime, int]]] = defaultdict(deque)
        # (hostname, source_ip) -> when that pair last crossed the brute force threshold
        self._brute_forced: dict[tuple[str, str], datetime] = {}

    def evaluate(self, event_id: int, event: TelemetryEvent) -> list[Match]:
        matches = []
        host = event.hostname.lower()

        if event.event_type == "process_creation" and event.process_name:
            process = normalize_process_name(event.process_name)
            if process in DISCOVERY_TOOLS:
                matches.append(Match("SEN-001", f"'{process}' was run by '{event.user}' on {event.hostname}.", [event_id]))
            if process in CREDENTIAL_TOOLS:
                matches.append(Match("SEN-005", f"Credential theft tool '{process}' was run by '{event.user}' on {event.hostname}.", [event_id]))

        elif event.event_type == "authentication_failure":
            source = event.source_ip or "an unknown source"
            if event.user.lower() in PRIVILEGED_USERS:
                matches.append(Match("SEN-002", f"Failed logon for '{event.user}' on {event.hostname} from {source}.", [event_id]))
            if event.source_ip:
                key = (host, event.source_ip)
                failures = self._failures[key]
                failures.append((event.timestamp, event_id))
                while failures and event.timestamp - failures[0][0] > self.window:
                    failures.popleft()
                if len(failures) >= self.threshold:
                    self._brute_forced[key] = event.timestamp
                    matches.append(Match(
                        "SEN-003",
                        f"{len(failures)} failed logons on {event.hostname} from {event.source_ip} within {int(self.window.total_seconds())}s.",
                        [failed_id for _, failed_id in failures],
                    ))

        elif event.event_type == "authentication_success" and event.source_ip:
            brute_forced_at = self._brute_forced.get((host, event.source_ip))
            if brute_forced_at and timedelta(0) <= event.timestamp - brute_forced_at <= self.follow_up:
                matches.append(Match(
                    "SEN-004",
                    f"'{event.user}' logged on to {event.hostname} from {event.source_ip}, which was brute forcing this host.",
                    [event_id],
                ))

        elif event.event_type == "account_created":
            matches.append(Match("SEN-006", f"'{event.user}' created account '{event.target_user}' on {event.hostname}.", [event_id]))

        elif event.event_type == "network_connection":
            if (event.bytes_out or 0) >= LARGE_UPLOAD_BYTES and event.dest_ip and is_external(event.dest_ip):
                size_mb = event.bytes_out // 1_000_000
                matches.append(Match("SEN-007", f"{event.hostname} sent {size_mb} MB to external IP {event.dest_ip}.", [event_id]))

        return matches
