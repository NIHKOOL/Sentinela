import pytest
from fastapi.testclient import TestClient

import server
from server import TelemetryEvent, evaluate_rules

client = TestClient(server.app)


@pytest.fixture(autouse=True)
def sent_alerts(monkeypatch):
    # Capture alerts instead of calling the real Discord webhook
    alerts = []
    monkeypatch.setattr(server, "dispatch_alert", lambda rule, event: alerts.append(rule["rule_id"]))
    return alerts


def make_event(**overrides) -> dict:
    event = {
        "hostname": "laptop-victim",
        "event_type": "process_creation",
        "user": "alice",
        "process_name": "notepad.exe",
    }
    event.update(overrides)
    return event


# --- Rule matching ---

def test_benign_process_does_not_alert():
    assert evaluate_rules(TelemetryEvent(**make_event())) == []


@pytest.mark.parametrize("process_name", [
    "whoami.exe",
    "WHOAMI.EXE",
    r"C:\Windows\System32\whoami.exe",
    "C:/Windows/System32/whoami.exe",
    "/usr/bin/whoami",
])
def test_suspicious_process_matches_regardless_of_path_and_case(process_name):
    matches = evaluate_rules(TelemetryEvent(**make_event(process_name=process_name)))
    assert [m["rule_id"] for m in matches] == ["SENTINELA-RULE-001"]


@pytest.mark.parametrize("user", ["root", "Administrator"])
def test_privileged_auth_failure_alerts(user):
    event = TelemetryEvent(**make_event(event_type="authentication_failure", user=user, source_ip="10.0.0.5"))
    matches = evaluate_rules(event)
    assert [m["rule_id"] for m in matches] == ["SENTINELA-RULE-002"]
    assert "10.0.0.5" in matches[0]["details"]


def test_privileged_auth_failure_without_ip_has_readable_details():
    event = TelemetryEvent(**make_event(event_type="authentication_failure", user="root"))
    details = evaluate_rules(event)[0]["details"]
    assert "None" not in details
    assert "unknown source" in details


def test_normal_user_auth_failure_does_not_alert():
    event = TelemetryEvent(**make_event(event_type="authentication_failure", user="alice"))
    assert evaluate_rules(event) == []


# --- Schema validation ---

def test_unknown_event_type_is_rejected():
    response = client.post("/api/v1/ingest", json=make_event(event_type="authentication_failed"))
    assert response.status_code == 422


def test_invalid_timestamp_is_rejected():
    response = client.post("/api/v1/ingest", json=make_event(timestamp="not-a-date"))
    assert response.status_code == 422


def test_missing_timestamp_is_filled_in():
    event = TelemetryEvent(**make_event())
    assert event.timestamp.tzinfo is not None


# --- API endpoints ---

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_ingest_benign_event(sent_alerts):
    response = client.post("/api/v1/ingest", json=make_event())
    assert response.status_code == 200
    assert response.json() == {"status": "processed", "alert_triggered": False, "rules": []}
    assert sent_alerts == []


def test_ingest_suspicious_event_dispatches_alert(sent_alerts):
    response = client.post("/api/v1/ingest", json=make_event(process_name="whoami.exe", command_line="whoami /all"))
    assert response.status_code == 200
    assert response.json() == {"status": "processed", "alert_triggered": True, "rules": ["SENTINELA-RULE-001"]}
    assert sent_alerts == ["SENTINELA-RULE-001"]
