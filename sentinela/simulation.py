"""The simulation: event pipeline, alerts, attacks, SOC triage and scoring.

Every event, whether background noise, an attacker step or a real event from
/ingest, goes through the same pipeline:

    event -> store -> detection rules -> alert (new or grouped) -> notify

Events, alerts and attacks are kept in SQLite (see storage.py), so a game
survives a restart. Correlation memory (e.g. recent failed logons) is not saved.

The simulation remembers which events came from the attacker ("ground truth").
The SOC views never show that, so the SOC has to work it out; the score compares.
"""
import json
import random
import threading
from datetime import datetime, timedelta
from typing import Callable, Optional

from . import activity, attacks
from .detection import Detector, Match
from .models import AlertUpdate, AttackRequest, TelemetryEvent, utc_now
from .organization import Organization
from .rules import RuleSet, load_rules
from .storage import Store

# Repeats of the same rule for the same host/user/source within this time join the existing alert
GROUP_WINDOW = timedelta(minutes=5)


class Simulation:
    def __init__(self, organization: Organization, notify: Callable[[dict], None] = lambda alert: None,
                 seed: Optional[int] = None, ruleset: Optional[RuleSet] = None, store: Optional[Store] = None):
        self.org = organization
        self.notify = notify
        self.rng = random.Random(seed)
        self.ruleset = ruleset if ruleset is not None else load_rules()
        self.detector = Detector(self.ruleset)
        self.store = store if store is not None else Store()  # in memory unless a file is given
        self.lock = threading.RLock()
        self.running = True
        self.interval_seconds = 3.0

    def reset(self):
        """Forget all events, alerts and attacks. The organization is kept."""
        with self.lock:
            self.store.clear()
            self.detector.reset()

    def reload_rules(self, ruleset: RuleSet):
        """Switch to newly loaded rules. Correlation memory (e.g. recent failed logons) starts empty."""
        with self.lock:
            self.ruleset = ruleset
            self.detector = Detector(ruleset)

    # --- Pipeline ---

    def ingest(self, event: TelemetryEvent, origin: str = "external", attack_id: Optional[int] = None) -> dict:
        with self.lock:
            new_alert_ids = []
            with self.store.transaction():
                event_id = self.store.add_event(event, origin, attack_id)
                for match in self.detector.evaluate(event_id, event):
                    alert_id, is_new = self._raise_alert(match, event)
                    self.store.link(alert_id, match.event_ids)
                    if is_new:
                        new_alert_ids.append(alert_id)

            # Saved first, then announced, so a slow Discord call never holds the database open
            for alert_id in new_alert_ids:
                alert = self.store.alert(alert_id)
                print(f"[!] ALERT {alert['rule_id']} [{alert['severity']}] {alert['details']}")
                self.notify(alert)
            return self.store.event(event_id)

    def _raise_alert(self, match: Match, event: TelemetryEvent) -> tuple[int, bool]:
        """Create a new alert, or join a matching open alert. Returns (alert id, is_new)."""
        group_key = json.dumps([match.rule_id, event.hostname.lower(), event.user.lower(), event.source_ip])
        for alert in self.store.open_alerts_in_group(group_key):
            last_seen = datetime.fromisoformat(alert["last_seen"])
            if event.timestamp - last_seen <= GROUP_WINDOW:
                self.store.update_alert(alert["id"], details=match.details,
                                        last_seen=max(last_seen, event.timestamp).isoformat())
                return alert["id"], False

        rule = match.rule
        asset = self.org.find_by_hostname(event.hostname)
        alert_id = self.store.add_alert({
            "rule_id": rule.id,
            "rule_name": rule.title,
            "severity": rule.severity,
            "mitre": rule.mitre,
            "details": match.details,
            "hostname": event.hostname,
            "asset_criticality": asset.criticality if asset else None,
            "user": event.user,
            "source_ip": event.source_ip,
            "first_seen": event.timestamp.isoformat(),
            "last_seen": event.timestamp.isoformat(),
            "status": "new",
            "verdict": None,
            "notes": "",
        }, group_key)
        return alert_id, True

    # --- Background activity ---

    def background_tick(self):
        for event in activity.generate(self.org.all(), self.rng):
            self.ingest(event, origin="background")

    def update_settings(self, running: Optional[bool] = None, interval_seconds: Optional[float] = None):
        if running is not None:
            self.running = running
        if interval_seconds is not None:
            self.interval_seconds = interval_seconds

    def settings(self) -> dict:
        return {"running": self.running, "interval_seconds": self.interval_seconds}

    # --- Attacker ---

    def launch_attack(self, request: AttackRequest) -> dict:
        scenario = attacks.SCENARIOS.get(request.scenario)
        if scenario is None:
            raise ValueError(f"Unknown scenario '{request.scenario}'.")
        target = self.org.get(request.target_id)
        if target is None:
            raise ValueError("Choose a target from the organization.")
        source = self.org.get(request.source_id) if request.source_id else None
        if scenario.needs_source and source is None:
            raise ValueError(f"'{scenario.name}' needs a source machine you already control.")
        if source is not None and source.id == target.id:
            raise ValueError("Source and target must be different machines.")

        succeeded = request.succeed and scenario.supports_success
        events = attacks.generate(scenario.id, target, source, succeeded, self.rng)
        with self.lock:
            attack_id = self.store.add_attack({
                "scenario": scenario.id,
                "name": scenario.name,
                "tactic": scenario.tactic,
                "mitre": scenario.mitre,
                "target": target.hostname,
                "source": source.hostname if source else None,
                "succeeded": succeeded,
                "launched_at": utc_now().isoformat(),
            })
            for event in events:
                self.ingest(event, origin="attack", attack_id=attack_id)
            return self._attack_view(self.store.attack(attack_id))

    @staticmethod
    def _attack_view(attack: dict) -> dict:
        return {**attack, "detected": bool(attack["detected_by"])}

    def list_attacks(self) -> list[dict]:
        with self.lock:
            return [self._attack_view(a) for a in self.store.list_attacks()]

    # --- SOC views (no ground truth) ---

    def list_events(self, limit: int = 100, **filters) -> list[dict]:
        """Events for the SOC; `filters` are the ones of Store.list_events (hostname, user, ip, search ...)."""
        # Newest first by event time (attack steps are backdated a few seconds, like late-arriving logs)
        with self.lock:
            return self.store.list_events(limit, **filters)

    def list_alerts(self, status: Optional[str] = None) -> list[dict]:
        with self.lock:
            return self.store.list_alerts(status)

    def get_alert(self, alert_id: int) -> Optional[dict]:
        with self.lock:
            alert = self.store.alert(alert_id)
            if alert is None:
                return None
            return {**alert, "events": self.store.events_by_ids(alert["event_ids"])}

    def update_alert(self, alert_id: int, update: AlertUpdate) -> Optional[dict]:
        with self.lock:
            alert = self.store.alert(alert_id)
            if alert is None:
                return None
            changes = {}
            if update.verdict is not None:
                changes["verdict"] = update.verdict
            if update.notes is not None:
                changes["notes"] = update.notes
            if update.status is not None:
                if update.status == "closed" and not changes.get("verdict", alert["verdict"]):
                    raise ValueError("Choose a verdict (true or false positive) before closing the alert.")
                changes["status"] = update.status
            if changes:
                with self.store.transaction():
                    self.store.update_alert(alert_id, **changes)
            return self.get_alert(alert_id)

    def stats(self) -> dict:
        with self.lock:
            open_alerts = self.store.list_alerts("open")
            by_severity = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
            by_host: dict[str, int] = {}
            for alert in open_alerts:
                by_severity[alert["severity"]] += 1
                by_host[alert["hostname"]] = by_host.get(alert["hostname"], 0) + 1
            return {
                "events_total": self.store.count_events(),
                "alerts_total": self.store.count_alerts(),
                "alerts_open": len(open_alerts),
                "open_by_severity": by_severity,
                "open_by_host": by_host,
                "attacks_total": len(self.store.list_attacks()),
                **self.settings(),
            }

    # --- Score (reveals ground truth) ---

    def score(self) -> dict:
        with self.lock:
            attack_views = self.list_attacks()
            detected = sum(1 for a in attack_views if a["detected"])

            debrief = []
            for alert in self.store.closed_alerts_with_truth():
                truth = "true_positive" if alert["from_attack"] else "false_positive"
                debrief.append({
                    "alert_id": alert["id"],
                    "rule_id": alert["rule_id"],
                    "rule_name": alert["rule_name"],
                    "hostname": alert["hostname"],
                    "verdict": alert["verdict"],
                    "truth": truth,
                    "correct": alert["verdict"] == truth,
                })
            correct = sum(1 for d in debrief if d["correct"])

            return {
                "attacks_launched": len(attack_views),
                "attacks_detected": detected,
                "attacks_missed": len(attack_views) - detected,
                "detection_rate": round(detected / len(attack_views), 2) if attack_views else None,
                "alerts_triaged": len(debrief),
                "triage_correct": correct,
                "triage_wrong": len(debrief) - correct,
                "triage_accuracy": round(correct / len(debrief), 2) if debrief else None,
                "alerts_open": len(self.store.list_alerts("open")),
                "missed_attacks": [a for a in reversed(attack_views) if not a["detected"]],
                "debrief": list(reversed(debrief)),
            }
