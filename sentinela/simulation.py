"""The simulation: event pipeline, alerts, attacks, SOC triage and scoring.

Every event, whether background noise, an attacker step or a real event from
/ingest, goes through the same pipeline:

    event -> store -> detection rules -> alert (new or grouped) -> notify

The simulation remembers which events came from the attacker ("ground truth").
The SOC views never show that, so the SOC has to work it out; the score compares.
"""
import random
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Callable, Optional

from . import activity, attacks
from .detection import RULES, Detector, Match
from .models import AlertUpdate, AttackRequest, TelemetryEvent, utc_now
from .organization import Organization

MAX_EVENTS = 5000
# Repeats of the same rule for the same host/user/source within this time join the existing alert
GROUP_WINDOW = timedelta(minutes=5)
HIDDEN_EVENT_FIELDS = {"origin"}


class Simulation:
    def __init__(self, organization: Organization, notify: Callable[[dict], None] = lambda alert: None,
                 seed: Optional[int] = None):
        self.org = organization
        self.notify = notify
        self.rng = random.Random(seed)
        self.detector = Detector()
        self.lock = threading.RLock()
        self.running = True
        self.interval_seconds = 3.0
        self.reset()

    def reset(self):
        """Forget all events, alerts and attacks. The organization is kept."""
        with self.lock:
            self.events: deque[dict] = deque(maxlen=MAX_EVENTS)  # newest first
            self.event_index: dict[int, dict] = {}
            self.alerts: dict[int, dict] = {}                      # oldest first
            self.attacks: dict[int, dict] = {}
            self.attack_by_event: dict[int, int] = {}
            self._counters = {"event": 0, "alert": 0, "attack": 0}
            self.detector.reset()

    def _next_id(self, kind: str) -> int:
        self._counters[kind] += 1
        return self._counters[kind]

    # --- Pipeline ---

    def ingest(self, event: TelemetryEvent, origin: str = "external", attack_id: Optional[int] = None) -> dict:
        with self.lock:
            event_id = self._next_id("event")
            stored = {"id": event_id, **event.model_dump(mode="json"), "origin": origin, "alert_ids": []}
            if len(self.events) == self.events.maxlen:
                self.event_index.pop(self.events[-1]["id"], None)
            self.events.appendleft(stored)
            self.event_index[event_id] = stored
            if attack_id is not None:
                self.attack_by_event[event_id] = attack_id

            for match in self.detector.evaluate(event_id, event):
                alert, is_new = self._raise_alert(match, event)
                for related_id in match.event_ids:
                    related = self.event_index.get(related_id)
                    if related is not None and alert["id"] not in related["alert_ids"]:
                        related["alert_ids"].append(alert["id"])
                if is_new:
                    print(f"[!] ALERT {alert['rule_id']} [{alert['severity']}] {alert['details']}")
                    self.notify(dict(alert))
            return stored

    def _raise_alert(self, match: Match, event: TelemetryEvent) -> tuple[dict, bool]:
        """Create a new alert, or add the events to a matching open alert. Returns (alert, is_new)."""
        key = (match.rule_id, event.hostname.lower(), event.user.lower(), event.source_ip)
        for alert in reversed(self.alerts.values()):
            if (alert["status"] != "closed" and alert["_key"] == key
                    and event.timestamp - datetime.fromisoformat(alert["last_seen"]) <= GROUP_WINDOW):
                for event_id in match.event_ids:
                    if event_id not in alert["event_ids"]:
                        alert["event_ids"].append(event_id)
                alert["count"] = len(alert["event_ids"])
                alert["details"] = match.details
                alert["last_seen"] = max(datetime.fromisoformat(alert["last_seen"]), event.timestamp).isoformat()
                return alert, False

        rule = RULES[match.rule_id]
        asset = self.org.find_by_hostname(event.hostname)
        alert = {
            "id": self._next_id("alert"),
            "rule_id": match.rule_id,
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "mitre": rule["mitre"],
            "details": match.details,
            "hostname": event.hostname,
            "asset_criticality": asset.criticality if asset else None,
            "user": event.user,
            "source_ip": event.source_ip,
            "first_seen": event.timestamp.isoformat(),
            "last_seen": event.timestamp.isoformat(),
            "event_ids": list(match.event_ids),
            "count": len(match.event_ids),
            "status": "new",
            "verdict": None,
            "notes": "",
            "_key": key,
        }
        self.alerts[alert["id"]] = alert
        return alert, True

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

        events = attacks.generate(scenario.id, target, source, request.succeed and scenario.supports_success, self.rng)
        with self.lock:
            attack = {
                "id": self._next_id("attack"),
                "scenario": scenario.id,
                "name": scenario.name,
                "tactic": scenario.tactic,
                "mitre": scenario.mitre,
                "target": target.hostname,
                "source": source.hostname if source else None,
                "succeeded": request.succeed and scenario.supports_success,
                "launched_at": utc_now().isoformat(),
                "event_ids": [],
            }
            self.attacks[attack["id"]] = attack
            for event in events:
                stored = self.ingest(event, origin="attack", attack_id=attack["id"])
                attack["event_ids"].append(stored["id"])
            return self._attack_view(attack)

    def _alert_attack_ids(self, alert: dict) -> set[int]:
        return {self.attack_by_event[e] for e in alert["event_ids"] if e in self.attack_by_event}

    def _attack_view(self, attack: dict) -> dict:
        detected_by = sorted({
            alert["rule_id"] for alert in self.alerts.values() if attack["id"] in self._alert_attack_ids(alert)
        })
        return {**attack, "detected": bool(detected_by), "detected_by": detected_by}

    def list_attacks(self) -> list[dict]:
        with self.lock:
            return [self._attack_view(a) for a in reversed(self.attacks.values())]

    # --- SOC views (no ground truth) ---

    @staticmethod
    def _public_event(event: dict) -> dict:
        return {k: v for k, v in event.items() if k not in HIDDEN_EVENT_FIELDS}

    @staticmethod
    def _public_alert(alert: dict) -> dict:
        return {k: v for k, v in alert.items() if not k.startswith("_")}

    def list_events(self, limit: int = 100, hostname: Optional[str] = None, search: Optional[str] = None) -> list[dict]:
        hostname = hostname.lower() if hostname else None
        search = search.lower() if search else None
        results = []
        with self.lock:
            # Newest first by event time (attack steps are backdated a few seconds, like late-arriving logs)
            for event in sorted(self.events, key=lambda e: e["timestamp"], reverse=True):
                if hostname and event["hostname"].lower() != hostname:
                    continue
                if search and not any(search in str(v).lower() for v in event.values() if v is not None):
                    continue
                results.append(self._public_event(event))
                if len(results) >= limit:
                    break
        return results

    def list_alerts(self, status: Optional[str] = None) -> list[dict]:
        with self.lock:
            alerts = reversed(self.alerts.values())
            if status == "open":
                alerts = (a for a in alerts if a["status"] != "closed")
            elif status:
                alerts = (a for a in alerts if a["status"] == status)
            return [self._public_alert(a) for a in alerts]

    def get_alert(self, alert_id: int) -> Optional[dict]:
        with self.lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                return None
            events = [self._public_event(self.event_index[e]) for e in alert["event_ids"] if e in self.event_index]
            return {**self._public_alert(alert), "events": events}

    def update_alert(self, alert_id: int, update: AlertUpdate) -> Optional[dict]:
        with self.lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                return None
            if update.verdict is not None:
                alert["verdict"] = update.verdict
            if update.notes is not None:
                alert["notes"] = update.notes
            if update.status is not None:
                if update.status == "closed" and not alert["verdict"]:
                    raise ValueError("Choose a verdict (true or false positive) before closing the alert.")
                alert["status"] = update.status
            return self.get_alert(alert_id)

    def stats(self) -> dict:
        with self.lock:
            open_alerts = [a for a in self.alerts.values() if a["status"] != "closed"]
            by_severity = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
            by_host: dict[str, int] = {}
            for alert in open_alerts:
                by_severity[alert["severity"]] += 1
                by_host[alert["hostname"]] = by_host.get(alert["hostname"], 0) + 1
            return {
                "events_total": self._counters["event"],
                "alerts_total": len(self.alerts),
                "alerts_open": len(open_alerts),
                "open_by_severity": by_severity,
                "open_by_host": by_host,
                "attacks_total": len(self.attacks),
                **self.settings(),
            }

    # --- Score (reveals ground truth) ---

    def score(self) -> dict:
        with self.lock:
            attack_views = [self._attack_view(a) for a in self.attacks.values()]
            detected = sum(1 for a in attack_views if a["detected"])

            debrief = []
            for alert in self.alerts.values():
                if alert["status"] != "closed":
                    continue
                truth = "true_positive" if self._alert_attack_ids(alert) else "false_positive"
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
                "alerts_open": sum(1 for a in self.alerts.values() if a["status"] != "closed"),
                "missed_attacks": [a for a in attack_views if not a["detected"]],
                "debrief": list(reversed(debrief)),
            }
