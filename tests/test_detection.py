"""The shipped rules in rules/ must keep detecting what they are meant to detect."""
from datetime import timedelta

import pytest

from sentinela.detection import Detector
from sentinela.models import TelemetryEvent, utc_now
from sentinela.rules import load_rules

RULESET = load_rules()


def event(**overrides) -> TelemetryEvent:
    data = {"hostname": "WS-ALICE", "event_type": "process_creation", "user": "alice", "process_name": "excel.exe"}
    data.update(overrides)
    return TelemetryEvent(**data)


def rule_ids(matches) -> list[str]:
    return [m.rule_id for m in matches]


def test_normal_program_does_not_match():
    assert Detector(RULESET).evaluate(1, event()) == []


@pytest.mark.parametrize("process_name", ["whoami.exe", "WHOAMI.EXE", r"C:\Windows\System32\whoami.exe", "/usr/bin/whoami"])
def test_discovery_matches_regardless_of_path_and_case(process_name):
    assert rule_ids(Detector(RULESET).evaluate(1, event(process_name=process_name))) == ["SEN-001"]


def test_credential_tool_is_critical_rule():
    assert rule_ids(Detector(RULESET).evaluate(1, event(process_name=r"C:\Users\Public\credential_dumper.exe"))) == ["SEN-005"]


def test_single_typo_is_not_brute_force():
    matches = Detector(RULESET).evaluate(1, event(event_type="authentication_failure", source_ip="10.0.1.11"))
    assert matches == []


def test_brute_force_needs_five_failures_within_window():
    detector = Detector(RULESET)
    start = utc_now()
    results = [
        detector.evaluate(i, event(event_type="authentication_failure", user="bob", source_ip="203.0.113.5",
                                   timestamp=start + timedelta(seconds=i)))
        for i in range(1, 6)
    ]
    assert all(r == [] for r in results[:4])
    assert rule_ids(results[4]) == ["SEN-003"]
    assert results[4][0].event_ids == [1, 2, 3, 4, 5]


def test_slow_failures_outside_window_are_not_brute_force():
    detector = Detector(RULESET)
    start = utc_now()
    for i in range(1, 8):
        matches = detector.evaluate(i, event(event_type="authentication_failure", user="bob", source_ip="203.0.113.5",
                                             timestamp=start + timedelta(seconds=30 * i)))
        assert "SEN-003" not in rule_ids(matches)


def test_success_after_brute_force_is_critical():
    detector = Detector(RULESET)
    start = utc_now()
    for i in range(5):
        detector.evaluate(i, event(event_type="authentication_failure", source_ip="203.0.113.5",
                                   timestamp=start + timedelta(seconds=i)))
    success = event(event_type="authentication_success", source_ip="203.0.113.5", timestamp=start + timedelta(seconds=10))
    assert rule_ids(detector.evaluate(99, success)) == ["SEN-004"]


def test_success_from_other_ip_is_fine():
    detector = Detector(RULESET)
    for i in range(5):
        detector.evaluate(i, event(event_type="authentication_failure", source_ip="203.0.113.5"))
    assert detector.evaluate(99, event(event_type="authentication_success", source_ip="10.0.1.11")) == []


def test_privileged_logon_failure():
    assert rule_ids(Detector(RULESET).evaluate(1, event(event_type="authentication_failure", user="Administrator"))) == ["SEN-002"]


def test_account_created():
    assert rule_ids(Detector(RULESET).evaluate(1, event(event_type="account_created", target_user="x"))) == ["SEN-006"]


@pytest.mark.parametrize("dest_ip,bytes_out,expected", [
    ("203.0.113.9", 300_000_000, ["SEN-007"]),
    ("10.0.0.30", 300_000_000, []),        # internal backup
    ("203.0.113.9", 2_000_000, []),         # small upload
])
def test_large_upload_to_internet(dest_ip, bytes_out, expected):
    e = event(event_type="network_connection", dest_ip=dest_ip, bytes_out=bytes_out)
    assert rule_ids(Detector(RULESET).evaluate(1, e)) == expected


def test_shipped_rules_load_without_errors():
    assert RULESET.errors == []
    assert [meta.id for meta in RULESET.alerting] == [f"SEN-00{n}" for n in range(1, 8)]


def test_building_block_rules_do_not_alert_by_themselves():
    # failed_logon and successful_logon only feed the correlations
    assert Detector(RULESET).evaluate(1, event(event_type="authentication_success", source_ip="10.0.1.11")) == []


@pytest.mark.parametrize("dest_ip", ["192.168.1.5", "172.20.0.9", "127.0.0.1"])
def test_large_upload_to_other_private_ranges_is_internal(dest_ip):
    e = event(event_type="network_connection", dest_ip=dest_ip, bytes_out=300_000_000)
    assert Detector(RULESET).evaluate(1, e) == []


def test_large_upload_without_destination_is_ignored():
    e = event(event_type="network_connection", bytes_out=300_000_000)
    assert Detector(RULESET).evaluate(1, e) == []


def test_alert_details_are_filled_in():
    [match] = Detector(RULESET).evaluate(1, event(process_name=r"C:\Windows\System32\WHOAMI.EXE"))
    assert match.details == "'whoami.exe' was run by 'alice' on WS-ALICE."
    [match] = Detector(RULESET).evaluate(1, event(event_type="authentication_failure", user="root"))
    assert match.details == "Failed logon for 'root' on WS-ALICE from unknown."


def test_timestamp_without_timezone_is_utc():
    assert event(timestamp="2026-10-05T10:00:00").timestamp.tzinfo is not None
