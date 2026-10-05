"""The Sigma-style rule engine: loading, validation, matching and correlation."""
from datetime import timedelta
from textwrap import dedent, indent

import pytest

from sentinela.detection import Detector
from sentinela.models import TelemetryEvent, utc_now
from sentinela.rules import load_rules


def ruleset_from(tmp_path, *files: str):
    for i, text in enumerate(files):
        (tmp_path / f"rule{i}.yml").write_text(dedent(text), encoding="utf-8")
    return load_rules(tmp_path)


def rule(detection: str, **extra) -> str:
    """A minimal alerting rule with the given detection block."""
    lines = ["title: Test rule", "id: T-1", "level: medium"] + [f"{k}: {v}" for k, v in extra.items()]
    return "\n".join(lines) + "\ndetection:\n" + indent(dedent(detection).strip("\n") + "\n", "  ")


def event(**overrides) -> TelemetryEvent:
    data = {"hostname": "WS-ALICE", "event_type": "process_creation", "user": "alice", "process_name": "excel.exe"}
    data.update(overrides)
    return TelemetryEvent(**data)


def fires(ruleset, **overrides) -> bool:
    assert ruleset.errors == []
    return bool(Detector(ruleset).evaluate(1, event(**overrides)))


# --- Matching values ---

@pytest.mark.parametrize("detection,process_name,expected", [
    ("process_name: excel.exe", "EXCEL.EXE", True),                         # case-insensitive
    ("process_name: excel.exe", "C:\\Office\\excel.exe", False),            # exact by default
    ("process_name|endswith: '\\excel.exe'", "C:\\Office\\excel.exe", True),
    ("process_name|startswith: 'C:\\Users'", "C:\\Users\\x\\tool.exe", True),
    ("process_name|contains: office", "C:\\Office\\excel.exe", True),
    ("process_name: 'C:\\*\\excel.exe'", "C:\\Office\\excel.exe", True),    # wildcard *
    ("process_name: 'excel.ex?'", "excel.exe", True),                       # wildcard ?
    ("process_name|re: '^ex.+\\.exe$'", "excel.exe", True),
    ("process_file: [word.exe, excel.exe]", "C:\\Office\\EXCEL.EXE", True),  # list = any
    ("Image|endswith: excel.exe", "C:\\Office\\excel.exe", True),           # Sigma alias
])
def test_value_matching(tmp_path, detection, process_name, expected):
    rs = ruleset_from(tmp_path, rule(f"  selection:\n    {detection}\n  condition: selection\n"))
    assert fires(rs, process_name=process_name) is expected


def test_all_modifier_requires_every_value(tmp_path):
    rs = ruleset_from(tmp_path, rule("""
      selection:
        command_line|contains|all: [net, user]
      condition: selection
    """))
    assert fires(rs, command_line="net user /domain")
    assert not fires(rs, command_line="net group")


@pytest.mark.parametrize("detection,overrides,expected", [
    ("bytes_out|gte: 100", {"bytes_out": 100}, True),
    ("bytes_out|gt: 100", {"bytes_out": 100}, False),
    ("bytes_out|lt: 100", {"bytes_out": 5}, True),
    ("dest_ip|cidr: 10.0.0.0/8", {"dest_ip": "10.1.2.3"}, True),
    ("dest_ip|cidr: 10.0.0.0/8", {"dest_ip": "203.0.113.5"}, False),
    ("dest_ip|cidr: 10.0.0.0/8", {"dest_ip": "not-an-ip"}, False),
    ("dest_ip|exists: true", {"dest_ip": "1.2.3.4"}, True),
    ("dest_ip|exists: false", {}, True),
    ("source_ip: null", {}, True),
    ("dest_port: 443", {"dest_port": 443}, True),
])
def test_numbers_networks_and_missing_values(tmp_path, detection, overrides, expected):
    rs = ruleset_from(tmp_path, rule(f"  selection:\n    {detection}\n  condition: selection\n"))
    assert fires(rs, event_type="network_connection", **overrides) is expected


def test_list_of_mappings_means_any(tmp_path):
    rs = ruleset_from(tmp_path, rule("""
      selection:
        - user: bob
        - process_name: excel.exe
      condition: selection
    """))
    assert fires(rs)                                   # second mapping matches
    assert not fires(rs, process_name="word.exe")


def test_keyword_list_searches_all_fields(tmp_path):
    rs = ruleset_from(tmp_path, rule("""
      keywords:
        - secret_plans
      condition: keywords
    """))
    assert fires(rs, command_line="copy secret_plans.docx")
    assert not fires(rs)


# --- Conditions ---

@pytest.mark.parametrize("condition,user,process,expected", [
    ("a and not b", "alice", "excel.exe", True),
    ("a and not b", "it-admin", "excel.exe", False),
    ("a or b", "it-admin", "word.exe", True),
    ("not (a or b)", "bob", "word.exe", True),
    ("1 of them", "bob", "excel.exe", True),
    ("all of them", "it-admin", "excel.exe", True),
    ("all of them", "alice", "excel.exe", False),
])
def test_conditions(tmp_path, condition, user, process, expected):
    rs = ruleset_from(tmp_path, rule(f"""
      a:
        process_name: excel.exe
      b:
        user: it-admin
      condition: {condition}
    """))
    assert fires(rs, user=user, process_name=process) is expected


def test_one_of_pattern(tmp_path):
    rs = ruleset_from(tmp_path, rule("""
      selection:
        event_type: process_creation
      filter_admin:
        user: it-admin
      filter_system:
        user: SYSTEM
      condition: selection and not 1 of filter_*
    """))
    assert fires(rs)
    assert not fires(rs, user="SYSTEM")


def test_logsource_limits_event_types(tmp_path):
    rs = ruleset_from(tmp_path, rule("""
      selection:
        user: alice
      condition: selection
    """, logsource="{category: authentication}"))
    assert not fires(rs)                                          # process_creation event
    assert fires(rs, event_type="authentication_failure")


def test_rules_without_id_do_not_alert(tmp_path):
    rs = ruleset_from(tmp_path, """
        title: Building block
        name: block
        detection:
          selection:
            user: alice
          condition: selection
    """)
    assert rs.errors == []
    assert rs.alerting == []
    assert Detector(rs).evaluate(1, event()) == []


def test_details_template(tmp_path):
    rs = ruleset_from(tmp_path, rule("""
      selection:
        user: alice
      condition: selection
    """, details='"{user} ran {process_file} on {hostname} from {source_ip}"'))
    [match] = Detector(rs).evaluate(1, event(process_name="C:\\Office\\EXCEL.EXE"))
    assert match.details == "alice ran excel.exe on WS-ALICE from unknown"


# --- Correlations ---

FAILED_LOGON = """
    title: Failed logon
    name: failed
    detection:
      selection:
        event_type: authentication_failure
      condition: selection
"""


def test_value_count_detects_password_spraying(tmp_path):
    rs = ruleset_from(tmp_path, FAILED_LOGON, """
        title: Password spraying
        id: SPRAY
        level: high
        correlation:
          type: value_count
          rules: [failed]
          group-by: [source_ip]
          timespan: 5m
          condition:
            field: user
            gte: 3
        details: "{count} different users tried from {source_ip}"
    """)
    assert rs.errors == []
    detector, start = Detector(rs), utc_now()
    results = [
        detector.evaluate(i, event(event_type="authentication_failure", user=user, source_ip="203.0.113.9",
                                   timestamp=start + timedelta(seconds=i)))
        for i, user in enumerate(["alice", "alice", "bob", "carol"], start=1)
    ]
    assert [bool(r) for r in results] == [False, False, False, True]
    assert results[-1][0].details == "3 different users tried from 203.0.113.9"


def test_temporal_needs_all_rules_within_timespan(tmp_path):
    rs = ruleset_from(tmp_path, FAILED_LOGON, """
        title: Program
        name: program
        detection:
          selection:
            event_type: process_creation
          condition: selection
    """, """
        title: Failure and program on same host
        id: BOTH
        level: medium
        correlation:
          type: temporal
          rules: [failed, program]
          group-by: [hostname]
          timespan: 1m
    """)
    detector, start = Detector(rs), utc_now()
    assert detector.evaluate(1, event(timestamp=start)) == []
    assert detector.evaluate(2, event(event_type="authentication_failure", timestamp=start + timedelta(seconds=30)))
    # Too far apart
    detector = Detector(rs)
    detector.evaluate(1, event(timestamp=start))
    assert detector.evaluate(2, event(event_type="authentication_failure", timestamp=start + timedelta(minutes=5))) == []


def test_events_missing_a_group_by_field_are_skipped(tmp_path):
    rs = ruleset_from(tmp_path, FAILED_LOGON, """
        title: Many failures
        id: MANY
        level: high
        correlation:
          type: event_count
          rules: [failed]
          group-by: [source_ip]
          timespan: 1m
          condition: {gte: 2}
    """)
    detector = Detector(rs)
    for i in range(5):
        assert detector.evaluate(i, event(event_type="authentication_failure")) == []   # no source_ip


# --- Errors: broken rules are reported, not fatal ---

@pytest.mark.parametrize("text,message", [
    ("title: [unclosed", "not valid YAML"),
    ("just text", "must be a mapping"),
    ("id: X\nlevel: low\ndetection: {s: {user: a}, condition: s}", "'title' is required"),
    ("title: T\ndetection: {s: {user: a}, condition: s}", "needs an 'id'"),
    ("title: T\nid: X\ndetection: {s: {user: a}, condition: s}", "'level' is required"),
    ("title: T\nid: X\nlevel: urgent\ndetection: {s: {user: a}, condition: s}", "'level' must be one of"),
    (rule("  s:\n    usr: a\n  condition: s\n"), "unknown field 'usr'"),
    (rule("  s:\n    user|endwith: a\n  condition: s\n"), "unknown modifier 'endwith'"),
    (rule("  s:\n    user: a\n  condition: s and t\n"), "unknown selection 't'"),
    (rule("  s:\n    user: a\n  condition: (s\n"), "missing a closing ')'"),
    (rule("  s:\n    user: a\n"), "needs a 'condition'"),
    (rule("  s:\n    user|re: '('\n  condition: s\n"), "invalid regular expression"),
    (rule("  s:\n    dest_ip|cidr: 999.0.0.0/8\n  condition: s\n"), "not a valid network"),
    (rule("  s:\n    bytes_out|gte: lots\n  condition: s\n"), "needs a number"),
    (rule("  s:\n    user: a\n  condition: s\n", details='"{nope}"'), "unknown placeholder"),
    (rule("  s:\n    user: a\n  condition: s\n", logsource="{category: dns}"), "unknown logsource category"),
    ("title: C\nid: C\nlevel: low\ncorrelation: {type: event_count, rules: [x], timespan: 1m, condition: {gte: 2}}",
     "unknown rule name(s): x"),
    ("title: C\nid: C\nlevel: low\ncorrelation: {type: magic, rules: [x], timespan: 1m}", "correlation 'type'"),
    ("title: C\nid: C\nlevel: low\ncorrelation: {type: event_count, rules: [x], timespan: soon, condition: {gte: 2}}",
     "'timespan' must look like"),
])
def test_invalid_rules_are_reported(tmp_path, text, message):
    rs = ruleset_from(tmp_path, text)
    assert len(rs.errors) == 1
    assert message in rs.errors[0]
    assert "rule0.yml" in rs.errors[0]


def test_one_broken_rule_does_not_stop_the_others(tmp_path):
    rs = ruleset_from(tmp_path, "title: [broken", rule("  s:\n    user: alice\n  condition: s\n"))
    assert len(rs.errors) == 1
    assert [m.id for m in rs.alerting] == ["T-1"]


def test_duplicate_ids_are_reported(tmp_path):
    good = rule("  s:\n    user: alice\n  condition: s\n")
    rs = ruleset_from(tmp_path, good, good)
    assert "already used" in rs.errors[0]
    assert len(rs.alerting) == 1


def test_circular_correlations_are_reported(tmp_path):
    # A needs B and B needs A: neither can ever be evaluated
    rs = ruleset_from(tmp_path, FAILED_LOGON, """
        title: A
        name: a
        correlation: {type: temporal, rules: [failed, b], timespan: 1m}
    """, """
        title: B
        name: b
        correlation: {type: temporal, rules: [failed, a], timespan: 1m}
    """)
    assert rs.correlations == []
    assert len(rs.errors) == 2
    assert all("circular reference" in e for e in rs.errors)


def test_missing_rules_folder(tmp_path):
    rs = load_rules(tmp_path / "nope")
    assert "not found" in rs.errors[0]


def test_yaml_cannot_run_code(tmp_path):
    # yaml.safe_load refuses Python object tags, so a rule file can never execute anything
    rs = ruleset_from(tmp_path, "title: !!python/object/apply:os.system ['echo hacked']")
    assert len(rs.errors) == 1
    assert "not valid YAML" in rs.errors[0]
