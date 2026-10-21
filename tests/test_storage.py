import pytest

from sentinela.models import AlertUpdate, AttackRequest, TelemetryEvent
from sentinela.organization import Organization
from sentinela.simulation import Simulation
from sentinela.storage import Store


@pytest.fixture
def org():
    return Organization()


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "sentinela.db"


def start(org, db_path, seed=1):
    return Simulation(org, seed=seed, store=Store(db_path))


def restart(sim, org, db_path):
    sim.store.close()
    return start(org, db_path, seed=2)


def whoami(user="bob"):
    return TelemetryEvent(hostname="DC01", event_type="process_creation", user=user,
                          process_name="C:\\Windows\\System32\\whoami.exe", command_line="whoami")


def launch(sim, scenario, target):
    return sim.launch_attack(AttackRequest(scenario=scenario, target_id=sim.org.find_by_hostname(target).id))


def test_game_survives_a_restart(org, db_path):
    sim = start(org, db_path)
    for _ in range(20):
        sim.background_tick()
    launch(sim, "credential_theft", "DC01")
    [theft] = [a for a in sim.list_alerts() if a["rule_id"] == "SEN-005"]
    sim.update_alert(theft["id"], AlertUpdate(status="closed", verdict="true_positive", notes="dumper on DC01"))
    before = (sim.list_alerts(), sim.list_attacks(), sim.list_events(limit=1000), sim.score(), sim.stats())

    sim = restart(sim, org, db_path)
    after = (sim.list_alerts(), sim.list_attacks(), sim.list_events(limit=1000), sim.score(), sim.stats())
    assert after == before
    assert sim.get_alert(theft["id"])["notes"] == "dumper on DC01"


def test_new_ids_continue_after_a_restart(org, db_path):
    sim = start(org, db_path)
    first = sim.ingest(whoami())
    sim = restart(sim, org, db_path)
    assert sim.ingest(whoami(user="carol"))["id"] == first["id"] + 1


def test_repeat_after_a_restart_joins_the_saved_alert(org, db_path):
    sim = start(org, db_path)
    sim.ingest(whoami())
    sim = restart(sim, org, db_path)
    sim.ingest(whoami())
    [alert] = sim.list_alerts()
    assert alert["rule_id"] == "SEN-001" and alert["count"] == 2


def test_reset_clears_the_saved_game(org, db_path):
    sim = start(org, db_path)
    sim.ingest(whoami())
    launch(sim, "credential_theft", "DC01")
    sim.reset()
    sim = restart(sim, org, db_path)
    assert sim.list_events() == [] and sim.list_alerts() == [] and sim.list_attacks() == []
    assert sim.ingest(whoami())["id"] == 1


def test_event_search_does_not_reveal_ground_truth(org, db_path):
    # origin is stored, but in its own column: searching for it must find nothing
    sim = start(org, db_path)
    for _ in range(20):
        sim.background_tick()
    launch(sim, "credential_theft", "DC01")
    assert sim.list_events(search="background") == []
    assert sim.list_events(search="attack") == []
    assert all("origin" not in e and "attack_id" not in e for e in sim.list_events(limit=1000))
    assert sim.list_events(search="CREDENTIAL_DUMPER")  # normal search still works, ignoring case
