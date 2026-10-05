import pytest
from fastapi.testclient import TestClient

from sentinela.api import create_app


@pytest.fixture
def client(tmp_path):
    # No `with` block, so the background activity loop does not run during tests
    return TestClient(create_app(data_dir=tmp_path, seed=1))


def asset_id(client, hostname):
    return next(a["id"] for a in client.get("/api/v1/assets").json() if a["hostname"] == hostname)


@pytest.mark.parametrize("path", ["/", "/organization", "/soc", "/attacker", "/static/style.css", "/static/common.js",
                                  "/static/logo-32.png", "/static/logo-64.png", "/static/logo-180.png", "/favicon.ico"])
def test_pages_are_served(client, path):
    assert client.get(path).status_code == 200


@pytest.mark.parametrize("path", ["/", "/soc", "/static/common.js", "/static/style.css"])
def test_pages_and_static_files_are_revalidated(client, path):
    # Without this, browsers may keep using an old common.js after an update
    assert client.get(path).headers["cache-control"] == "no-cache"


def test_health(client):
    assert client.get("/health").json()["status"] == "online"


def test_sample_organization_is_loaded(client):
    hostnames = {a["hostname"] for a in client.get("/api/v1/assets").json()}
    assert {"DC01", "WEB01", "DB01", "WS-ALICE"} <= hostnames


def test_add_edit_delete_asset_and_persist(client, tmp_path):
    new = {"hostname": "WS-ERIN", "ip": "10.0.1.15", "os": "Windows 11", "role": "workstation", "users": ["erin"]}
    created = client.post("/api/v1/assets", json=new)
    assert created.status_code == 201
    new_id = created.json()["id"]
    assert (tmp_path / "organization.json").exists()

    updated = client.put(f"/api/v1/assets/{new_id}", json={**new, "department": "Legal"})
    assert updated.json()["department"] == "Legal"

    # Survives a restart
    restarted = TestClient(create_app(data_dir=tmp_path))
    assert any(a["hostname"] == "WS-ERIN" for a in restarted.get("/api/v1/assets").json())

    assert client.delete(f"/api/v1/assets/{new_id}").status_code == 204
    assert client.delete(f"/api/v1/assets/{new_id}").status_code == 404


@pytest.mark.parametrize("change,status", [
    ({"hostname": "dc01"}, 409),          # duplicate hostname (case-insensitive)
    ({"ip": "10.0.0.10"}, 409),           # duplicate IP
    ({"ip": "not-an-ip"}, 422),
    ({"hostname": "bad name!"}, 422),
    ({"role": "toaster"}, 422),
])
def test_invalid_assets_are_rejected(client, change, status):
    asset = {"hostname": "NEW01", "ip": "10.0.9.9", "os": "Windows 11", "role": "server", **change}
    assert client.post("/api/v1/assets", json=asset).status_code == status


def test_reset_to_sample(client):
    client.delete(f"/api/v1/assets/{asset_id(client, 'DC01')}")
    client.post("/api/v1/assets/reset")
    assert asset_id(client, "DC01")


def test_attack_to_triage_to_score(client):
    launched = client.post("/api/v1/attacks", json={"scenario": "credential_theft", "target_id": asset_id(client, "DC01")})
    assert launched.status_code == 201
    assert launched.json()["detected_by"] == ["SEN-005"]

    alert = client.get("/api/v1/alerts?status=open").json()[0]
    assert alert["severity"] == "CRITICAL"
    assert client.get(f"/api/v1/alerts/{alert['id']}").json()["events"][0]["hostname"] == "DC01"

    bad_close = client.patch(f"/api/v1/alerts/{alert['id']}", json={"status": "closed"})
    assert bad_close.status_code == 400

    closed = client.patch(f"/api/v1/alerts/{alert['id']}", json={"status": "closed", "verdict": "true_positive"})
    assert closed.json()["status"] == "closed"

    score = client.get("/api/v1/score").json()
    assert score["attacks_detected"] == 1
    assert score["triage_correct"] == 1


def test_bad_attack_requests(client):
    assert client.post("/api/v1/attacks", json={"scenario": "nope", "target_id": "x"}).status_code == 400
    assert client.post("/api/v1/attacks", json={"scenario": "lateral_movement",
                                                "target_id": asset_id(client, "DB01")}).status_code == 400


def test_ingest_from_real_agent(client):
    response = client.post("/api/v1/ingest", json={
        "hostname": "WS-BOB", "event_type": "process_creation", "user": "bob",
        "process_name": r"C:\Windows\System32\whoami.exe",
    })
    assert response.json()["alert_triggered"] is True
    assert client.post("/api/v1/ingest", json={"hostname": "x", "event_type": "bogus", "user": "u"}).status_code == 422


def test_event_search_and_host_filter(client):
    client.post("/api/v1/attacks", json={"scenario": "discovery", "target_id": asset_id(client, "DC01")})
    client.post("/api/v1/attacks", json={"scenario": "exfiltration", "target_id": asset_id(client, "DB01")})
    assert {e["hostname"] for e in client.get("/api/v1/events?hostname=dc01").json()} == {"DC01"}
    assert all("net" in (e["command_line"] or "") for e in client.get("/api/v1/events?search=net user").json())


def test_simulation_settings_and_reset(client):
    assert client.patch("/api/v1/simulation", json={"running": False, "interval_seconds": 6}).json() == \
        {"running": False, "interval_seconds": 6}
    assert client.patch("/api/v1/simulation", json={"interval_seconds": 0}).status_code == 422

    client.post("/api/v1/attacks", json={"scenario": "discovery", "target_id": asset_id(client, "DC01")})
    client.post("/api/v1/simulation/reset")
    stats = client.get("/api/v1/stats").json()
    assert stats["events_total"] == 0
    assert stats["attacks_total"] == 0
