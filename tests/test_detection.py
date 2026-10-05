from datetime import timedelta

import pytest

from sentinela.detection import Detector, is_external
from sentinela.models import TelemetryEvent, utc_now


def event(**overrides) -> TelemetryEvent:
    data = {"hostname": "WS-ALICE", "event_type": "process_creation", "user": "alice", "process_name": "excel.exe"}
    data.update(overrides)
    return TelemetryEvent(**data)


def rule_ids(matches) -> list[str]:
    return [m.rule_id for m in matches]


def test_normal_program_does_not_match():
    assert Detector().evaluate(1, event()) == []


@pytest.mark.parametrize("process_name", ["whoami.exe", "WHOAMI.EXE", r"C:\Windows\System32\whoami.exe", "/usr/bin/whoami"])
def test_discovery_matches_regardless_of_path_and_case(process_name):
    assert rule_ids(Detector().evaluate(1, event(process_name=process_name))) == ["SEN-001"]


def test_credential_tool_is_critical_rule():
    assert rule_ids(Detector().evaluate(1, event(process_name=r"C:\Users\Public\credential_dumper.exe"))) == ["SEN-005"]


def test_single_typo_is_not_brute_force():
    matches = Detector().evaluate(1, event(event_type="authentication_failure", source_ip="10.0.1.11"))
    assert matches == []


def test_brute_force_needs_five_failures_within_window():
    detector = Detector()
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
    detector = Detector()
    start = utc_now()
    for i in range(1, 8):
        matches = detector.evaluate(i, event(event_type="authentication_failure", user="bob", source_ip="203.0.113.5",
                                             timestamp=start + timedelta(seconds=30 * i)))
        assert "SEN-003" not in rule_ids(matches)


def test_success_after_brute_force_is_critical():
    detector = Detector()
    start = utc_now()
    for i in range(5):
        detector.evaluate(i, event(event_type="authentication_failure", source_ip="203.0.113.5",
                                   timestamp=start + timedelta(seconds=i)))
    success = event(event_type="authentication_success", source_ip="203.0.113.5", timestamp=start + timedelta(seconds=10))
    assert rule_ids(detector.evaluate(99, success)) == ["SEN-004"]


def test_success_from_other_ip_is_fine():
    detector = Detector()
    for i in range(5):
        detector.evaluate(i, event(event_type="authentication_failure", source_ip="203.0.113.5"))
    assert detector.evaluate(99, event(event_type="authentication_success", source_ip="10.0.1.11")) == []


def test_privileged_logon_failure():
    assert rule_ids(Detector().evaluate(1, event(event_type="authentication_failure", user="Administrator"))) == ["SEN-002"]


def test_account_created():
    assert rule_ids(Detector().evaluate(1, event(event_type="account_created", target_user="x"))) == ["SEN-006"]


@pytest.mark.parametrize("dest_ip,bytes_out,expected", [
    ("203.0.113.9", 300_000_000, ["SEN-007"]),
    ("10.0.0.30", 300_000_000, []),        # internal backup
    ("203.0.113.9", 2_000_000, []),         # small upload
])
def test_large_upload_to_internet(dest_ip, bytes_out, expected):
    e = event(event_type="network_connection", dest_ip=dest_ip, bytes_out=bytes_out)
    assert rule_ids(Detector().evaluate(1, e)) == expected


def test_is_external():
    assert is_external("203.0.113.7")
    assert not is_external("10.0.0.1")
    assert not is_external("192.168.1.5")
    assert not is_external("not-an-ip")


def test_timestamp_without_timezone_is_utc():
    assert event(timestamp="2026-10-05T10:00:00").timestamp.tzinfo is not None
