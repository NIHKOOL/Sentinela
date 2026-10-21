"""SQLite storage for events, alerts and attacks, so a game survives a restart.

Everything lives in one database file (data/sentinela.db). Without a path the
database is kept in memory only (used by tests). The Simulation's lock makes
sure only one thread uses the connection at a time.

Ground truth (an event's `origin` and `attack_id`) has its own columns and is
never part of the event data the SOC sees or searches.
"""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Optional

from .models import TelemetryEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    id          INTEGER PRIMARY KEY,
    scenario    TEXT NOT NULL,
    name        TEXT NOT NULL,
    tactic      TEXT NOT NULL,
    mitre       TEXT NOT NULL,
    target      TEXT NOT NULL,
    source      TEXT,
    succeeded   INTEGER NOT NULL,
    launched_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,        -- UTC, fixed format so text order = time order
    hostname  TEXT NOT NULL,
    data      TEXT NOT NULL,        -- the event as JSON: what the SOC may see
    origin    TEXT NOT NULL,        -- ground truth: background / attack / external
    attack_id INTEGER REFERENCES attacks(id)
);
CREATE INDEX IF NOT EXISTS events_by_time ON events (timestamp);
CREATE INDEX IF NOT EXISTS events_by_attack ON events (attack_id);

CREATE TABLE IF NOT EXISTS alerts (
    id                INTEGER PRIMARY KEY,
    rule_id           TEXT NOT NULL,
    rule_name         TEXT NOT NULL,
    severity          TEXT NOT NULL,
    mitre             TEXT NOT NULL,
    details           TEXT NOT NULL,
    hostname          TEXT NOT NULL,
    asset_criticality TEXT,
    user              TEXT NOT NULL,
    source_ip         TEXT,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    status            TEXT NOT NULL,
    verdict           TEXT,
    notes             TEXT NOT NULL,
    group_key         TEXT NOT NULL     -- rule + host + user + source, for grouping repeats
);
CREATE INDEX IF NOT EXISTS alerts_by_group ON alerts (group_key);

-- Which events belong to which alert (one event can be in several alerts)
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    event_id INTEGER NOT NULL REFERENCES events(id),
    PRIMARY KEY (alert_id, event_id)
);
CREATE INDEX IF NOT EXISTS alert_events_by_event ON alert_events (event_id);
"""

ALERT_FIELDS = ["id", "rule_id", "rule_name", "severity", "mitre", "details", "hostname", "asset_criticality",
                "user", "source_ip", "first_seen", "last_seen", "status", "verdict", "notes"]
ALERT_COLUMNS = ", ".join(f"a.{name}" for name in ALERT_FIELDS)
# Event and alert ids as JSON lists, in the order they were linked
ALERT_EVENT_IDS = ("(SELECT json_group_array(event_id) FROM (SELECT event_id FROM alert_events "
                   "WHERE alert_id = a.id ORDER BY rowid)) AS event_ids")
EVENT_ALERT_IDS = ("(SELECT json_group_array(alert_id) FROM (SELECT alert_id FROM alert_events "
                   "WHERE event_id = e.id ORDER BY rowid)) AS alert_ids")


class Store:
    def __init__(self, path: Optional[Path] = None):
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path) if path else ":memory:", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        if path:
            self.db.execute("PRAGMA journal_mode = WAL")  # safer writes, readers do not block the writer
        self.db.executescript(SCHEMA)

    @contextmanager
    def transaction(self):
        """Group several writes: all are saved together, or none if an error happens."""
        with self.db:
            yield

    def close(self):
        self.db.close()

    def clear(self):
        with self.db:
            for table in ("alert_events", "alerts", "events", "attacks"):
                self.db.execute(f"DELETE FROM {table}")

    # --- Events ---

    def add_event(self, event: TelemetryEvent, origin: str, attack_id: Optional[int]) -> int:
        cursor = self.db.execute(
            "INSERT INTO events (timestamp, hostname, data, origin, attack_id) VALUES (?, ?, ?, ?, ?)",
            (event.timestamp.isoformat(timespec="microseconds"), event.hostname,
             json.dumps(event.model_dump(mode="json")), origin, attack_id))
        return cursor.lastrowid

    def event(self, event_id: int) -> Optional[dict]:
        events = self.events_by_ids([event_id])
        return events[0] if events else None

    def events_by_ids(self, event_ids: list[int]) -> list[dict]:
        """The events in the order of `event_ids`; unknown ids are skipped."""
        if not event_ids:
            return []
        marks = ", ".join("?" * len(event_ids))
        rows = self.db.execute(f"SELECT e.id, e.data, {EVENT_ALERT_IDS} FROM events e WHERE e.id IN ({marks})",
                               event_ids).fetchall()
        by_id = {row["id"]: _event(row) for row in rows}
        return [by_id[i] for i in event_ids if i in by_id]

    def list_events(self, limit: int, hostname: Optional[str] = None, search: Optional[str] = None) -> list[dict]:
        """Newest first by event time. `search` looks in every field the SOC can see, ignoring case."""
        sql = f"SELECT e.id, e.data, {EVENT_ALERT_IDS} FROM events e WHERE 1 = 1"
        params: list = []
        if hostname:
            sql += " AND lower(e.hostname) = lower(?)"
            params.append(hostname)
        if search:
            sql += (" AND EXISTS (SELECT 1 FROM json_each(e.data) f "
                    "WHERE f.value IS NOT NULL AND instr(lower(CAST(f.value AS TEXT)), lower(?)) > 0)")
            params.append(search)
        sql += " ORDER BY e.timestamp DESC, e.id DESC LIMIT ?"
        params.append(limit)
        return [_event(row) for row in self.db.execute(sql, params)]

    def count_events(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # --- Alerts ---

    def add_alert(self, alert: dict, group_key: str) -> int:
        fields = [name for name in ALERT_FIELDS if name != "id"]
        cursor = self.db.execute(
            f"INSERT INTO alerts ({', '.join(fields)}, group_key) VALUES ({', '.join('?' * (len(fields) + 1))})",
            [alert[name] for name in fields] + [group_key])
        return cursor.lastrowid

    def update_alert(self, alert_id: int, **changes):
        unknown = set(changes) - set(ALERT_FIELDS)
        if unknown:
            raise ValueError(f"Unknown alert fields: {sorted(unknown)}")
        assignments = ", ".join(f"{name} = ?" for name in changes)
        self.db.execute(f"UPDATE alerts SET {assignments} WHERE id = ?", [*changes.values(), alert_id])

    def link(self, alert_id: int, event_ids: Iterable[int]):
        """Add events to an alert. Ids already linked or no longer stored are skipped."""
        for event_id in event_ids:
            self.db.execute("INSERT OR IGNORE INTO alert_events (alert_id, event_id) "
                            "SELECT ?, id FROM events WHERE id = ?", (alert_id, event_id))

    def open_alerts_in_group(self, group_key: str) -> list[dict]:
        """Not-closed alerts with this group key, newest first: only `id` and `last_seen`."""
        rows = self.db.execute("SELECT id, last_seen FROM alerts WHERE group_key = ? AND status != 'closed' "
                               "ORDER BY id DESC", (group_key,))
        return [dict(row) for row in rows]

    def alert(self, alert_id: int) -> Optional[dict]:
        row = self.db.execute(f"SELECT {ALERT_COLUMNS}, {ALERT_EVENT_IDS} FROM alerts a WHERE a.id = ?",
                              (alert_id,)).fetchone()
        return _alert(row) if row else None

    def list_alerts(self, status: Optional[str] = None) -> list[dict]:
        """Newest first. `status` 'open' means every status except closed."""
        sql = f"SELECT {ALERT_COLUMNS}, {ALERT_EVENT_IDS} FROM alerts a"
        params: list = []
        if status == "open":
            sql += " WHERE a.status != 'closed'"
        elif status:
            sql += " WHERE a.status = ?"
            params.append(status)
        sql += " ORDER BY a.id DESC"
        return [_alert(row) for row in self.db.execute(sql, params)]

    def count_alerts(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def closed_alerts_with_truth(self) -> list[dict]:
        """Closed alerts, oldest first, each with `from_attack`: True if any of its events came from an attack."""
        rows = self.db.execute(
            f"SELECT {ALERT_COLUMNS}, EXISTS (SELECT 1 FROM alert_events ae JOIN events e ON e.id = ae.event_id "
            "WHERE ae.alert_id = a.id AND e.attack_id IS NOT NULL) AS from_attack "
            "FROM alerts a WHERE a.status = 'closed' ORDER BY a.id")
        return [{**dict(row), "from_attack": bool(row["from_attack"])} for row in rows]

    # --- Attacks ---

    def add_attack(self, attack: dict) -> int:
        with self.db:
            cursor = self.db.execute(
                "INSERT INTO attacks (scenario, name, tactic, mitre, target, source, succeeded, launched_at) "
                "VALUES (:scenario, :name, :tactic, :mitre, :target, :source, :succeeded, :launched_at)", attack)
        return cursor.lastrowid

    def list_attacks(self, attack_id: Optional[int] = None) -> list[dict]:
        """Newest first, each with its `event_ids` and the rules that detected it (`detected_by`)."""
        sql = ("SELECT t.*, "
               "(SELECT json_group_array(id) FROM (SELECT id FROM events WHERE attack_id = t.id ORDER BY id)) "
               "AS event_ids, "
               "(SELECT json_group_array(rule_id) FROM (SELECT DISTINCT a.rule_id FROM alerts a "
               "JOIN alert_events ae ON ae.alert_id = a.id JOIN events e ON e.id = ae.event_id "
               "WHERE e.attack_id = t.id ORDER BY a.rule_id)) AS detected_by "
               "FROM attacks t")
        params: list = []
        if attack_id is not None:
            sql += " WHERE t.id = ?"
            params.append(attack_id)
        rows = self.db.execute(sql + " ORDER BY t.id DESC", params)
        return [{**dict(row), "succeeded": bool(row["succeeded"]), "event_ids": json.loads(row["event_ids"]),
                 "detected_by": json.loads(row["detected_by"])} for row in rows]

    def attack(self, attack_id: int) -> Optional[dict]:
        attacks = self.list_attacks(attack_id)
        return attacks[0] if attacks else None


def _event(row: sqlite3.Row) -> dict:
    return {"id": row["id"], **json.loads(row["data"]), "alert_ids": json.loads(row["alert_ids"])}


def _alert(row: sqlite3.Row) -> dict:
    alert = {name: row[name] for name in ALERT_FIELDS}
    event_ids = json.loads(row["event_ids"])
    return {**alert, "event_ids": event_ids, "count": len(event_ids)}
