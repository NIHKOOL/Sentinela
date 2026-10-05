"""Sigma-style detection rules, loaded from the YAML files in rules/.

Sentinela supports the core of the Sigma format (https://sigmahq.io):

* Detection rules: `logsource`, named selections, field modifiers
  (contains, startswith, endswith, re, cidr, gt, gte, lt, lte, exists, all),
  wildcards (* and ?), keyword lists, and conditions with
  and / or / not / parentheses / "1 of", "all of" and "them".
* Correlation rules: event_count, value_count, temporal and temporal_ordered,
  with group-by and timespan.

Differences from Sigma, to keep things simple:

* A rule raises alerts only if it has an `id` (like SEN-001). Rules with only a
  `name` are building blocks for correlation rules (Sigma uses `generate` for this).
* Field names are Sentinela's own (process_name, source_ip, ...). Common Sigma
  names such as Image or CommandLine are accepted as aliases.
* `details` (optional) is a message template for the alert, e.g. "{user} on {hostname}".

Files are read with yaml.safe_load, so a rule file can only contain plain data.
"""
import ntpath
import operator
import re
from dataclasses import dataclass, field
from datetime import timedelta
from fnmatch import fnmatchcase
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from .models import TelemetryEvent

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

LEVELS = {"informational": "LOW", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}

# logsource.category -> the Sentinela event types it covers
LOGSOURCE_CATEGORIES = {
    "process_creation": {"process_creation"},
    "authentication": {"authentication_success", "authentication_failure"},
    "network_connection": {"network_connection"},
    "account_management": {"account_created"},
}

# Extra fields computed for every event, so rules can stay simple
DERIVED_FIELDS = {
    "process_file": "lowercase file name of process_name, e.g. 'whoami.exe'",
    "bytes_out_mb": "bytes_out in whole megabytes",
}
EVENT_FIELDS = set(TelemetryEvent.model_fields) | set(DERIVED_FIELDS)

# Common Sigma field names -> Sentinela field names
FIELD_ALIASES = {
    "Image": "process_name",
    "CommandLine": "command_line",
    "User": "user",
    "SubjectUserName": "user",
    "TargetUserName": "target_user",
    "IpAddress": "source_ip",
    "SourceIp": "source_ip",
    "DestinationIp": "dest_ip",
    "DestinationPort": "dest_port",
    "Computer": "hostname",
    "ComputerName": "hostname",
}

STRING_MODIFIERS = {"contains", "startswith", "endswith"}
COMPARISONS = {"gt": operator.gt, "gte": operator.ge, "lt": operator.lt, "lte": operator.le, "eq": operator.eq}
VALUE_MODIFIERS = STRING_MODIFIERS | {"re", "cidr", "exists"} | {"gt", "gte", "lt", "lte"}
CORRELATION_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}
EXTRA_PLACEHOLDERS = {"count", "timespan", "title", "id"}
TIMESPAN_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
PLACEHOLDER = re.compile(r"\{(\w+)\}")


class RuleError(Exception):
    """A rule file or rule is invalid. The message says where and why."""


def event_fields(event: TelemetryEvent) -> dict:
    """The values a rule can test: the event's fields plus the derived ones."""
    fields = event.model_dump()
    fields["process_file"] = ntpath.basename(event.process_name).lower() if event.process_name else None
    fields["bytes_out_mb"] = event.bytes_out // 1_000_000 if event.bytes_out is not None else None
    return fields


# --- Rule metadata ---

@dataclass
class RuleMeta:
    title: str
    file: str
    kind: str                      # "detection" or a correlation type
    id: Optional[str] = None
    name: Optional[str] = None
    severity: Optional[str] = None
    description: str = ""
    status: str = ""
    author: str = ""
    mitre: str = ""
    tactics: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    details_template: Optional[str] = None

    @property
    def alerting(self) -> bool:
        return self.id is not None

    @property
    def key(self) -> str:
        return self.id or self.name

    def render(self, values: dict) -> str:
        template = self.details_template or "{title} on {hostname} (user {user})."
        values = {**values, "title": self.title, "id": self.id}
        return PLACEHOLDER.sub(lambda m: _display(values.get(m.group(1))), template)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.title,
            "severity": self.severity,
            "mitre": self.mitre,
            "tactics": self.tactics,
            "description": self.description,
            "falsepositives": self.falsepositives,
            "status": self.status,
            "type": self.kind,
            "file": self.file,
        }


def _display(value: Any) -> str:
    if value is None:
        return "unknown"
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


@dataclass
class DetectionRule:
    meta: RuleMeta
    event_types: Optional[set[str]]
    selections: dict[str, Callable[[dict], bool]]
    condition: Callable[[Callable[[str], bool]], bool]

    def matches(self, fields: dict) -> bool:
        if self.event_types is not None and fields.get("event_type") not in self.event_types:
            return False
        cache: dict[str, bool] = {}

        def selection(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name](fields)
            return cache[name]

        return self.condition(selection)


@dataclass
class CorrelationRule:
    meta: RuleMeta
    type: str
    rules: list[str]
    group_by: list[str]
    timespan: timedelta
    timespan_text: str
    threshold: Optional[Callable[[int], bool]] = None
    value_field: Optional[str] = None


@dataclass
class RuleSet:
    directory: Optional[Path]
    detections: list[DetectionRule]
    correlations: list[CorrelationRule]   # in dependency order
    errors: list[str]

    @property
    def alerting(self) -> list[RuleMeta]:
        rules = [r.meta for r in [*self.detections, *self.correlations] if r.meta.alerting]
        return sorted(rules, key=lambda meta: meta.id)

    def get(self, rule_id: str) -> Optional[RuleMeta]:
        return next((meta for meta in self.alerting if meta.id == rule_id), None)


# --- Loading ---

def load_rules(directory: Path = DEFAULT_RULES_DIR) -> RuleSet:
    """Load every *.yml / *.yaml file in `directory`. Broken rules are skipped and listed in `errors`."""
    directory = Path(directory)
    errors: list[str] = []
    documents: list[tuple[str, dict]] = []

    if not directory.is_dir():
        return RuleSet(directory, [], [], [f"Rules folder not found: {directory}"])

    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        try:
            with path.open(encoding="utf-8") as f:
                loaded = list(yaml.safe_load_all(f))
        except yaml.YAMLError as e:
            errors.append(f"{path.name}: not valid YAML ({_short_yaml_error(e)})")
            continue
        except OSError as e:
            errors.append(f"{path.name}: could not be read ({e})")
            continue
        for index, document in enumerate(loaded, start=1):
            if document is None:
                continue
            label = path.name if len(loaded) == 1 else f"{path.name} (rule {index})"
            if not isinstance(document, dict):
                errors.append(f"{label}: a rule must be a mapping of keys like title, detection, level")
                continue
            documents.append((label, document))

    return build_ruleset(documents, directory, errors)


def build_ruleset(documents: list[tuple[str, dict]], directory: Optional[Path] = None,
                  errors: Optional[list[str]] = None) -> RuleSet:
    errors = list(errors or [])
    rules: list[DetectionRule | CorrelationRule] = []
    for label, document in documents:
        try:
            if "correlation" in document:
                rules.append(_parse_correlation(document, label))
            else:
                rules.append(_parse_detection(document, label))
        except RuleError as e:
            errors.append(str(e))

    # IDs and names must be unique
    unique, ids, names = [], set(), set()
    for rule in rules:
        meta = rule.meta
        if meta.id and meta.id in ids:
            errors.append(f"{meta.file}: id '{meta.id}' is already used by another rule")
            continue
        if meta.name and meta.name in names:
            errors.append(f"{meta.file}: name '{meta.name}' is already used by another rule")
            continue
        ids.add(meta.id)
        names.add(meta.name)
        unique.append(rule)

    detections = [r for r in unique if isinstance(r, DetectionRule)]
    correlations = _resolve_correlations([r for r in unique if isinstance(r, CorrelationRule)], detections, errors)
    return RuleSet(directory, detections, correlations, errors)


def _resolve_correlations(correlations: list[CorrelationRule], detections: list[DetectionRule],
                          errors: list[str]) -> list[CorrelationRule]:
    """Drop correlations that reference unknown rules or form a loop; return the rest in dependency order."""
    detection_names = {r.meta.name for r in detections if r.meta.name}
    remaining = list(correlations)
    while True:
        known = detection_names | {c.meta.name for c in remaining if c.meta.name}
        broken = [c for c in remaining if any(name not in known for name in c.rules)]
        if not broken:
            break
        for c in broken:
            missing = ", ".join(name for name in c.rules if name not in known)
            errors.append(f"{c.meta.file}: correlation refers to unknown rule name(s): {missing}")
            remaining.remove(c)

    ordered: list[CorrelationRule] = []
    done = set(detection_names)
    while remaining:
        ready = [c for c in remaining if all(name in done for name in c.rules)]
        if not ready:
            for c in remaining:
                errors.append(f"{c.meta.file}: correlation is part of a circular reference")
            break
        for c in ready:
            ordered.append(c)
            remaining.remove(c)
            if c.meta.name:
                done.add(c.meta.name)
    return ordered


# --- Parsing: shared metadata ---

def _parse_meta(doc: dict, label: str, kind: str) -> RuleMeta:
    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        raise RuleError(f"{label}: 'title' is required")
    where = f"{label} '{title}'"

    rule_id = doc.get("id")
    if rule_id is not None and (not isinstance(rule_id, str) or not rule_id.strip()):
        raise RuleError(f"{where}: 'id' must be text, like SEN-008")
    name = doc.get("name")
    if name is not None and (not isinstance(name, str) or not NAME_PATTERN.match(name)):
        raise RuleError(f"{where}: 'name' may only contain letters, numbers, '_', '-' and '.'")
    if rule_id is None and name is None:
        raise RuleError(f"{where}: needs an 'id' (to raise alerts) or a 'name' (to be used by a correlation rule)")

    level = doc.get("level")
    severity = None
    if level is not None:
        if str(level).lower() not in LEVELS:
            raise RuleError(f"{where}: 'level' must be one of {', '.join(LEVELS)}")
        severity = LEVELS[str(level).lower()]
    elif rule_id is not None:
        raise RuleError(f"{where}: 'level' is required for rules that raise alerts")

    tags = doc.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise RuleError(f"{where}: 'tags' must be a list of text values")
    techniques, tactics = [], []
    for tag in tags:
        lowered = tag.lower()
        if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", lowered):
            techniques.append(lowered.removeprefix("attack.").upper())
        elif lowered.startswith("attack."):
            tactics.append(lowered.removeprefix("attack.").replace("_", " ").replace("-", " ").title())

    falsepositives = doc.get("falsepositives") or []
    if isinstance(falsepositives, str):
        falsepositives = [falsepositives]
    if not isinstance(falsepositives, list):
        raise RuleError(f"{where}: 'falsepositives' must be a list of text values")

    details = doc.get("details")
    if details is not None:
        if not isinstance(details, str):
            raise RuleError(f"{where}: 'details' must be text")
        allowed = EVENT_FIELDS | EXTRA_PLACEHOLDERS
        unknown = [p for p in PLACEHOLDER.findall(details) if p not in allowed]
        if unknown:
            raise RuleError(f"{where}: unknown placeholder(s) in 'details': {', '.join(unknown)}. "
                            f"Use event fields, count, timespan, title or id.")

    return RuleMeta(
        title=title.strip(), file=label, kind=kind, id=rule_id, name=name, severity=severity,
        description=str(doc.get("description") or "").strip(), status=str(doc.get("status") or ""),
        author=str(doc.get("author") or ""), mitre=" / ".join(techniques), tactics=tactics,
        falsepositives=[str(fp) for fp in falsepositives], details_template=details,
    )


def _field_name(raw: str, where: str) -> str:
    name = FIELD_ALIASES.get(raw, raw)
    if name not in EVENT_FIELDS:
        raise RuleError(f"{where}: unknown field '{raw}'. Known fields: {', '.join(sorted(EVENT_FIELDS))}")
    return name


# --- Parsing: detection rules ---

def _parse_detection(doc: dict, label: str) -> DetectionRule:
    meta = _parse_meta(doc, label, "detection")
    where = f"{label} '{meta.title}'"

    event_types = None
    logsource = doc.get("logsource")
    if logsource is not None:
        if not isinstance(logsource, dict):
            raise RuleError(f"{where}: 'logsource' must be a mapping, e.g. category: process_creation")
        category = logsource.get("category")
        if category is not None:
            if category not in LOGSOURCE_CATEGORIES:
                raise RuleError(f"{where}: unknown logsource category '{category}'. "
                                f"Use one of: {', '.join(LOGSOURCE_CATEGORIES)}")
            event_types = LOGSOURCE_CATEGORIES[category]

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise RuleError(f"{where}: 'detection' is required (selections plus a 'condition')")
    detection = dict(detection)
    condition = detection.pop("condition", None)
    if condition is None:
        raise RuleError(f"{where}: 'detection' needs a 'condition', e.g. condition: selection")
    if not detection:
        raise RuleError(f"{where}: 'detection' needs at least one selection")
    selections = {str(name): _compile_selection(str(name), body, where) for name, body in detection.items()}

    conditions = condition if isinstance(condition, list) else [condition]
    compiled = [_ConditionParser(str(c), selections, where).parse() for c in conditions]
    combined = compiled[0] if len(compiled) == 1 else (lambda sel: any(c(sel) for c in compiled))
    return DetectionRule(meta, event_types, selections, combined)


def _compile_selection(name: str, body: Any, where: str) -> Callable[[dict], bool]:
    where = f"{where}, selection '{name}'"
    if isinstance(body, dict):
        if not body:
            raise RuleError(f"{where}: is empty")
        tests = [_compile_field(str(key), value, where) for key, value in body.items()]
        return lambda fields: all(test(fields) for test in tests)
    if isinstance(body, list) and body:
        if all(isinstance(item, dict) for item in body):
            # A list of mappings: any one of them may match
            options = [_compile_selection(name, item, where) for item in body]
            return lambda fields: any(option(fields) for option in options)
        if all(not isinstance(item, (dict, list)) for item in body):
            # A keyword list: the text appears in any field
            patterns = [_wildcard(f"*{_text(k)}*") for k in body]
            return lambda fields: any(
                p.fullmatch(_text(v)) for v in fields.values() if v is not None for p in patterns)
    raise RuleError(f"{where}: must be a mapping of field: value, a list of mappings, or a list of keywords")


def _compile_field(key: str, expected: Any, where: str) -> Callable[[dict], bool]:
    raw_name, *modifiers = key.split("|")
    name = _field_name(raw_name, where)
    match_all = "all" in modifiers
    modifiers = [m for m in modifiers if m != "all"]
    for m in modifiers:
        if m not in VALUE_MODIFIERS:
            raise RuleError(f"{where}: unknown modifier '{m}' in '{key}'. "
                            f"Supported: {', '.join(sorted(VALUE_MODIFIERS | {'all'}))}")
    if len(modifiers) > 1:
        raise RuleError(f"{where}: '{key}' uses more than one modifier (only 'all' can be combined)")
    modifier = modifiers[0] if modifiers else None

    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise RuleError(f"{where}: '{key}' has an empty list")
    if any(isinstance(v, (dict, list)) for v in values):
        raise RuleError(f"{where}: '{key}' values must be single values, not lists or mappings")
    tests = [_compile_value(modifier, v, f"{where}, '{key}'") for v in values]
    combine = all if match_all else any
    return lambda fields: combine(test(fields.get(name)) for test in tests)


def _compile_value(modifier: Optional[str], expected: Any, where: str) -> Callable[[Any], bool]:
    if modifier == "exists":
        if not isinstance(expected, bool):
            raise RuleError(f"{where}: 'exists' needs true or false")
        return lambda actual: (actual is not None) == expected

    if expected is None:
        if modifier:
            raise RuleError(f"{where}: null can only be used without a modifier")
        return lambda actual: actual is None

    if modifier in COMPARISONS:
        if isinstance(expected, bool) or not isinstance(expected, (int, float)):
            raise RuleError(f"{where}: '{modifier}' needs a number")
        compare = COMPARISONS[modifier]

        def test_number(actual):
            try:
                return compare(float(actual), float(expected))
            except (TypeError, ValueError):
                return False
        return test_number

    if modifier == "cidr":
        try:
            network = ip_network(str(expected), strict=False)
        except ValueError:
            raise RuleError(f"{where}: '{expected}' is not a valid network, e.g. 10.0.0.0/8")

        def test_network(actual):
            try:
                return actual is not None and ip_address(str(actual)) in network
            except ValueError:
                return False
        return test_network

    if modifier == "re":
        try:
            pattern = re.compile(str(expected))
        except re.error as e:
            raise RuleError(f"{where}: invalid regular expression ({e})")
        return lambda actual: actual is not None and pattern.search(_text(actual)) is not None

    text = _text(expected)
    if modifier == "contains":
        text = f"*{text}*"
    elif modifier == "startswith":
        text = f"{text}*"
    elif modifier == "endswith":
        text = f"*{text}"
    pattern = _wildcard(text)
    return lambda actual: actual is not None and pattern.fullmatch(_text(actual)) is not None


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _wildcard(text: str) -> re.Pattern:
    """Sigma wildcards: * = any text, ? = one character. Matching ignores upper/lower case."""
    regex = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in text)
    return re.compile(regex, re.IGNORECASE | re.DOTALL)


class _ConditionParser:
    """Turns 'selection and not (filter1 or 1 of filter_*)' into a function."""

    TOKEN = re.compile(r"\(|\)|[^\s()]+")
    KEYWORDS = {"and", "or", "not", "of", "them", "(", ")"}

    def __init__(self, text: str, selections: dict, where: str):
        self.text = text
        self.tokens = self.TOKEN.findall(text)
        self.selections = selections
        self.where = f"{where}, condition '{text}'"
        self.pos = 0

    def error(self, message: str) -> RuleError:
        return RuleError(f"{self.where}: {message}")

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def take(self) -> str:
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def parse(self):
        if not self.tokens:
            raise self.error("is empty")
        node = self.parse_or()
        if self.pos != len(self.tokens):
            raise self.error(f"unexpected '{self.tokens[self.pos]}'")
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek() == "or":
            self.take()
            left, right = node, self.parse_and()
            node = lambda sel, l=left, r=right: l(sel) or r(sel)
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.peek() == "and":
            self.take()
            left, right = node, self.parse_not()
            node = lambda sel, l=left, r=right: l(sel) and r(sel)
        return node

    def parse_not(self):
        if self.peek() == "not":
            self.take()
            inner = self.parse_not()
            return lambda sel: not inner(sel)
        return self.parse_primary()

    def parse_primary(self):
        token = self.peek()
        if token is None:
            raise self.error("ends too early")
        if token == "(":
            self.take()
            node = self.parse_or()
            if self.peek() != ")":
                raise self.error("is missing a closing ')'")
            self.take()
            return node
        if token in ("1", "any", "all") and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            self.take()
            self.take()
            if self.peek() is None:
                raise self.error(f"'{token} of' needs a selection name, a pattern like filter_*, or 'them'")
            target = self.take()
            if target.lower() == "them":
                names = [n for n in self.selections if not n.startswith("_")]
            else:
                names = [n for n in self.selections if fnmatchcase(n, target)]
            if not names:
                raise self.error(f"no selection matches '{target}'")
            quantifier = all if token == "all" else any
            return lambda sel: quantifier(sel(n) for n in names)
        if token in self.KEYWORDS:
            raise self.error(f"unexpected '{self.tokens[self.pos]}'")
        name = self.take()
        if name not in self.selections:
            raise self.error(f"unknown selection '{name}'. Defined: {', '.join(self.selections)}")
        return lambda sel: sel(name)


# --- Parsing: correlation rules ---

def _parse_correlation(doc: dict, label: str) -> CorrelationRule:
    correlation = doc.get("correlation")
    kind = correlation.get("type") if isinstance(correlation, dict) else None
    meta = _parse_meta(doc, label, str(kind))
    where = f"{label} '{meta.title}'"
    if not isinstance(correlation, dict):
        raise RuleError(f"{where}: 'correlation' must be a mapping with type, rules, timespan, ...")
    if kind not in CORRELATION_TYPES:
        raise RuleError(f"{where}: correlation 'type' must be one of {', '.join(sorted(CORRELATION_TYPES))}")

    rules = correlation.get("rules")
    if isinstance(rules, str):
        rules = [rules]
    if not isinstance(rules, list) or not rules or not all(isinstance(r, str) for r in rules):
        raise RuleError(f"{where}: correlation 'rules' must list the names of other rules")
    if kind.startswith("temporal") and len(rules) < 2:
        raise RuleError(f"{where}: a {kind} correlation needs at least two rules")

    group_by = correlation.get("group-by") or []
    if isinstance(group_by, str):
        group_by = [group_by]
    if not isinstance(group_by, list):
        raise RuleError(f"{where}: 'group-by' must be a list of field names")
    group_by = [_field_name(str(f), where) for f in group_by]

    timespan_text = str(correlation.get("timespan", ""))
    match = re.fullmatch(r"(\d+)([smhd])", timespan_text)
    if not match or int(match.group(1)) == 0:
        raise RuleError(f"{where}: 'timespan' must look like 60s, 10m, 1h or 1d")
    timespan = timedelta(seconds=int(match.group(1)) * TIMESPAN_UNITS[match.group(2)])

    threshold, value_field = None, None
    if kind in ("event_count", "value_count"):
        condition = correlation.get("condition")
        if not isinstance(condition, dict):
            raise RuleError(f"{where}: {kind} needs a 'condition', e.g. condition: {{gte: 5}}")
        condition = dict(condition)
        if kind == "value_count":
            if "field" not in condition:
                raise RuleError(f"{where}: value_count needs 'field' in its condition (the field whose different values are counted)")
            value_field = _field_name(str(condition.pop("field")), where)
        if len(condition) != 1 or next(iter(condition)) not in COMPARISONS:
            raise RuleError(f"{where}: 'condition' needs exactly one of {', '.join(COMPARISONS)}, e.g. gte: 5")
        op_name, number = next(iter(condition.items()))
        if isinstance(number, bool) or not isinstance(number, int):
            raise RuleError(f"{where}: the '{op_name}' value must be a whole number")
        compare = COMPARISONS[op_name]
        threshold = lambda count: compare(count, number)

    return CorrelationRule(meta, kind, rules, group_by, timespan, timespan_text, threshold, value_field)


def _short_yaml_error(error: yaml.YAMLError) -> str:
    mark = getattr(error, "problem_mark", None)
    problem = getattr(error, "problem", None) or str(error).splitlines()[0]
    return f"line {mark.line + 1}: {problem}" if mark else problem
