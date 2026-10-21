"""The Windows agent, tested with sample Security log XML (reading the real log needs admin rights)."""
import json

import pytest

from agent import windows_agent as agent
from sentinela.models import TelemetryEvent
from sentinela.organization import Organization
from sentinela.simulation import Simulation


def xml_event(event_id: int, record_id: int, **data: str) -> str:
    fields = "".join(f"<Data Name='{name}'>{value}</Data>" for name, value in data.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-Security-Auditing'/>"
        f"<EventID>{event_id}</EventID><TimeCreated SystemTime='2026-10-21T09:43:00.3429328Z'/>"
        f"<EventRecordID>{record_id}</EventRecordID><Channel>Security</Channel>"
        f"<Computer>Desktop-EAMZK1516.home.lan</Computer></System><EventData>{fields}</EventData></Event>"
    )


def wrap(*events: str) -> str:
    return f"<Events>{''.join(events)}</Events>"


WHOAMI = xml_event(4688, 101, SubjectUserName="nihkool", TargetUserName="-",
                   NewProcessName="C:\\Windows\\System32\\whoami.exe", CommandLine="whoami /all")
LOGON = xml_event(4624, 102, SubjectUserName="DESKTOP-EAMZK1516$", TargetUserName="nihkool",
                  LogonType="2", IpAddress="127.0.0.1")
FAILED = xml_event(4625, 103, TargetUserName="administrator", LogonType="3", IpAddress="192.168.1.50")
NEW_ACCOUNT = xml_event(4720, 104, SubjectUserName="nihkool", TargetUserName="backup-admin")
SERVICE_LOGON = xml_event(4624, 105, TargetUserName="SYSTEM", LogonType="5", IpAddress="-")
MACHINE_PROCESS = xml_event(4688, 106, SubjectUserName="DESKTOP-EAMZK1516$", TargetUserName="-",
                            NewProcessName="C:\\Windows\\System32\\svchost.exe", CommandLine="-")


def telemetry(xml: str, **kwargs):
    [raw] = agent.parse_events(wrap(xml))
    return agent.to_telemetry(raw, **kwargs)


def test_parse_events():
    [raw] = agent.parse_events(wrap(WHOAMI))
    assert raw["event_id"] == 4688 and raw["record_id"] == 101
    assert raw["computer"] == "Desktop-EAMZK1516.home.lan"
    assert raw["data"]["CommandLine"] == "whoami /all"


@pytest.mark.parametrize("xml,expected", [
    (WHOAMI, {"event_type": "process_creation", "user": "nihkool",
              "process_name": "C:\\Windows\\System32\\whoami.exe", "command_line": "whoami /all"}),
    (LOGON, {"event_type": "authentication_success", "user": "nihkool", "source_ip": "127.0.0.1"}),
    (FAILED, {"event_type": "authentication_failure", "user": "administrator", "source_ip": "192.168.1.50"}),
    (NEW_ACCOUNT, {"event_type": "account_created", "user": "nihkool", "target_user": "backup-admin"}),
])
def test_windows_events_become_sentinela_events(xml, expected):
    event = telemetry(xml)
    assert event == {"timestamp": "2026-10-21T09:43:00.342932Z", "hostname": "Desktop-EAMZK1516", **expected}
    TelemetryEvent(**event)  # accepted by Sentinela's schema


@pytest.mark.parametrize("xml", [SERVICE_LOGON, MACHINE_PROCESS])
def test_windows_own_accounts_are_skipped(xml):
    assert telemetry(xml) is None


def test_windows_own_accounts_can_be_included():
    event = telemetry(MACHINE_PROCESS, include_system=True)
    assert event["user"] == "SYSTEM" and "command_line" not in event   # '-' means empty


@pytest.mark.parametrize("logon_type", ["0", "4", "5", "9"])
def test_logons_not_caused_by_a_person_are_skipped(logon_type):
    assert telemetry(xml_event(4624, 1, TargetUserName="nihkool", LogonType=logon_type)) is None


def test_query_asks_only_for_collected_events_after_the_bookmark():
    query = agent.security_query(after_record_id=500)
    assert all(f"EventID={i}" in query for i in (4688, 4624, 4625, 4720))
    assert query.endswith("and EventRecordID>500]]")


def test_state_file_round_trip(tmp_path):
    path = tmp_path / "sub" / "agent-state.json"
    assert agent.load_state(path) is None
    agent.save_state(path, 1234)
    assert agent.load_state(path) == 1234


def test_real_whoami_triggers_a_detection():
    # A real 'whoami' from this PC goes through the same rules as simulated events
    sim = Simulation(Organization(), seed=1)
    stored = sim.ingest(TelemetryEvent(**telemetry(WHOAMI)))
    assert [a["rule_id"] for a in sim.list_alerts() if a["id"] in stored["alert_ids"]] == ["SEN-001"]


def test_handle_sends_and_stops_at_the_first_failure(monkeypatch, capsys):
    raws = agent.parse_events(wrap(WHOAMI, SERVICE_LOGON, LOGON, FAILED))
    sent = []

    def fake_send(server, event, key):
        assert key == "s3cret"
        if event["event_type"] == "authentication_failure":
            raise agent.urllib.error.URLError("connection refused")
        sent.append(event["event_type"])
        return {"alert_triggered": False, "alert_ids": []}

    monkeypatch.setattr(agent, "send", fake_send)
    args = agent.argparse.Namespace(include_system=False, key="s3cret")
    last = agent.handle(raws, args, "http://127.0.0.1:8000")
    assert sent == ["process_creation", "authentication_success"]   # the service logon was skipped, not sent
    assert last == 102            # the failed send (103) is retried next time
    assert "Will retry" in capsys.readouterr().out


def test_dry_run_prints_json(capsys):
    args = agent.argparse.Namespace(include_system=False)
    assert agent.handle(agent.parse_events(wrap(WHOAMI)), args, None) == 101
    assert json.loads(capsys.readouterr().out)["command_line"] == "whoami /all"


def test_rejected_event_stops_the_agent(monkeypatch):
    # A wrong key will not fix itself: stop with a clear message instead of retrying forever
    def refuse(server, event, key):
        raise agent.RejectedError("Sentinela refused the event (HTTP 401).")

    monkeypatch.setattr(agent, "send", refuse)
    args = agent.argparse.Namespace(include_system=False, key="wrong")
    with pytest.raises(agent.RejectedError):
        agent.handle(agent.parse_events(wrap(WHOAMI)), args, "http://192.168.1.10:8000")


def test_key_comes_from_the_environment_not_the_command_line(monkeypatch):
    monkeypatch.setenv(agent.KEY_ENV, "s3cret")
    monkeypatch.setattr(agent, "run", lambda args: args.key)
    assert agent.main(["--once"]) == "s3cret"
    with pytest.raises(SystemExit):
        agent.main(["--key", "s3cret"])   # no such option


def test_the_agents_own_wevtutil_is_skipped():
    # The agent runs wevtutil every few seconds; Windows logs that as 4688 with the agent as parent (hex pid)
    own = xml_event(4688, 200, SubjectUserName="nihkool", TargetUserName="-", ProcessId="0x1f40",
                    NewProcessName="C:\Windows\System32\wevtutil.exe", CommandLine="wevtutil qe Security")
    assert telemetry(own, own_pid=0x1F40) is None
    assert telemetry(own, own_pid=1234) is not None   # the same command from another process is kept
