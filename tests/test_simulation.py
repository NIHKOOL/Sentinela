import random

import pytest

from sentinela import activity, attacks
from sentinela.models import AlertUpdate, AttackRequest, TelemetryEvent
from sentinela.organization import Organization
from sentinela.simulation import Simulation


@pytest.fixture
def notified():
    return []


@pytest.fixture
def sim(notified):
    return Simulation(Organization(), notify=notified.append, seed=1)


def asset(sim, hostname):
    return sim.org.find_by_hostname(hostname)


def attack(sim, scenario, target, source=None, succeed=False):
    return sim.launch_attack(AttackRequest(
        scenario=scenario, target_id=asset(sim, target).id,
        source_id=asset(sim, source).id if source else None, succeed=succeed,
    ))


# --- Attacks ---

@pytest.mark.parametrize("scenario,expected_rules", [
    ("discovery", ["SEN-001"]),
    ("credential_theft", ["SEN-005"]),
    ("backdoor_account", ["SEN-006"]),
    ("exfiltration", ["SEN-007"]),
])
def test_attack_steps_are_detected(sim, scenario, expected_rules):
    result = attack(sim, scenario, "DC01")
    assert result["detected"]
    assert result["detected_by"] == expected_rules


def test_password_guessing_with_success_triggers_brute_force_and_critical(sim):
    result = attack(sim, "password_guessing", "DC01", succeed=True)
    assert result["succeeded"]
    assert set(result["detected_by"]) == {"SEN-002", "SEN-003", "SEN-004"}


def test_lateral_movement_is_a_detection_gap(sim):
    result = attack(sim, "lateral_movement", "DB01", source="WS-BOB")
    assert not result["detected"]
    assert sim.score()["missed_attacks"][0]["scenario"] == "lateral_movement"


def test_lateral_movement_needs_a_different_source(sim):
    with pytest.raises(ValueError):
        attack(sim, "lateral_movement", "DB01")
    with pytest.raises(ValueError):
        attack(sim, "lateral_movement", "DB01", source="DB01")


def test_unknown_scenario_and_target_are_rejected(sim):
    with pytest.raises(ValueError):
        sim.launch_attack(AttackRequest(scenario="nope", target_id=asset(sim, "DC01").id))
    with pytest.raises(ValueError):
        sim.launch_attack(AttackRequest(scenario="discovery", target_id="missing"))


def test_linux_targets_get_linux_events(sim):
    attack(sim, "password_guessing", "WEB01")
    assert all(e["user"] == "root" for e in sim.list_events())


def test_every_scenario_has_a_builder():
    assert set(attacks.SCENARIOS) == set(attacks.BUILDERS)


# --- Alerts ---

def test_repeated_matches_are_grouped_into_one_alert(sim):
    attack(sim, "password_guessing", "DC01")
    brute_force = [a for a in sim.list_alerts() if a["rule_id"] == "SEN-003"]
    assert len(brute_force) == 1
    assert brute_force[0]["count"] >= 5


def test_new_alerts_are_notified_once(sim, notified):
    attack(sim, "password_guessing", "DC01")
    assert sorted(a["rule_id"] for a in notified) == ["SEN-002", "SEN-003"]


def test_soc_views_hide_ground_truth(sim):
    attack(sim, "discovery", "DC01")
    for event in sim.list_events():
        assert "origin" not in event
    alert = sim.list_alerts()[0]
    assert not any(key.startswith("_") for key in alert)
    assert "origin" not in sim.get_alert(alert["id"])["events"][0]


def test_closing_needs_a_verdict(sim):
    attack(sim, "discovery", "DC01")
    alert_id = sim.list_alerts()[0]["id"]
    with pytest.raises(ValueError):
        sim.update_alert(alert_id, AlertUpdate(status="closed"))
    closed = sim.update_alert(alert_id, AlertUpdate(status="closed", verdict="true_positive", notes="real"))
    assert closed["status"] == "closed"
    assert closed["notes"] == "real"


# --- Score ---

def test_score_compares_verdicts_with_ground_truth(sim):
    attack(sim, "credential_theft", "DC01")
    # A false positive: an admin running whoami as part of their job
    sim.ingest(TelemetryEvent(hostname="DB01", event_type="process_creation", user="it-admin", process_name="whoami.exe"),
               origin="background")

    alerts = {a["rule_id"]: a["id"] for a in sim.list_alerts()}
    sim.update_alert(alerts["SEN-005"], AlertUpdate(status="closed", verdict="true_positive"))
    sim.update_alert(alerts["SEN-001"], AlertUpdate(status="closed", verdict="true_positive"))  # wrong

    score = sim.score()
    assert score["attacks_launched"] == 1
    assert score["attacks_detected"] == 1
    assert score["alerts_triaged"] == 2
    assert score["triage_correct"] == 1
    assert score["triage_accuracy"] == 0.5
    truths = {d["rule_id"]: d["truth"] for d in score["debrief"]}
    assert truths == {"SEN-005": "true_positive", "SEN-001": "false_positive"}


def test_reset_clears_everything_but_the_organization(sim):
    attack(sim, "discovery", "DC01")
    assets_before = len(sim.org.all())
    sim.reset()
    assert sim.list_events() == []
    assert sim.list_alerts() == []
    assert sim.list_attacks() == []
    assert len(sim.org.all()) == assets_before


# --- Background activity ---

def test_background_activity_is_mostly_quiet(sim):
    for _ in range(200):
        sim.background_tick()
    stats = sim.stats()
    assert stats["events_total"] > 200
    # Some false positives on purpose, but far fewer alerts than events
    assert stats["alerts_total"] < stats["events_total"] / 10
    assert sim.list_attacks() == []


def test_background_activity_with_no_assets():
    assert activity.generate([], random.Random(0)) == []
