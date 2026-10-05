"""Detection engine: runs the YAML rules (see rules/ and sentinela/rules.py) against events.

Detection rules look at one event. Correlation rules remember earlier matches
and look for a pattern over time, separately for each group-by value
(for example each host + source IP pair).
"""
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .models import TelemetryEvent
from .rules import CorrelationRule, RuleMeta, RuleSet, event_fields, load_rules


@dataclass
class Match:
    rule: RuleMeta
    details: str
    event_ids: list[int]

    @property
    def rule_id(self) -> str:
        return self.rule.id


class Detector:
    def __init__(self, ruleset: Optional[RuleSet] = None):
        self.ruleset = ruleset if ruleset is not None else load_rules()
        self.reset()

    def reset(self):
        # (correlation key, group-by values) -> what that correlation remembers for that group
        self._state: dict[tuple, object] = {}

    def evaluate(self, event_id: int, event: TelemetryEvent) -> list[Match]:
        fields = event_fields(event)
        hits: dict[str, list[int]] = {}   # rule name -> event ids, for correlations further down
        matches: list[Match] = []

        for rule in self.ruleset.detections:
            if rule.matches(fields):
                if rule.meta.name:
                    hits[rule.meta.name] = [event_id]
                if rule.meta.alerting:
                    matches.append(Match(rule.meta, rule.meta.render(fields), [event_id]))

        # Correlations run in dependency order, so one correlation can build on another
        for correlation in self.ruleset.correlations:
            hit_names = [name for name in correlation.rules if name in hits]
            if not hit_names:
                continue
            group = tuple(fields.get(f) for f in correlation.group_by)
            if any(value is None for value in group):
                continue
            result = self._update(correlation, group, event.timestamp, event_id, fields, hit_names, hits)
            if result is None:
                continue
            event_ids, extra = result
            if correlation.meta.name:
                hits[correlation.meta.name] = event_ids
            if correlation.meta.alerting:
                values = {**fields, **extra, "timespan": correlation.timespan_text}
                matches.append(Match(correlation.meta, correlation.meta.render(values), event_ids))

        return matches

    def _update(self, correlation: CorrelationRule, group: tuple, now: datetime, event_id: int,
                fields: dict, hit_names: list[str], hits: dict[str, list[int]]):
        """Record this event for the correlation. Returns (event_ids, extra values) when it fires."""
        key = (correlation.meta.key, group)

        if correlation.type == "event_count":
            window = self._state.setdefault(key, deque())
            window.append((now, event_id))
            self._forget_old(window, now, correlation)
            if correlation.threshold(len(window)):
                return [e for _, e in window], {"count": len(window)}
            return None

        if correlation.type == "value_count":
            value = fields.get(correlation.value_field)
            if value is None:
                return None
            window = self._state.setdefault(key, deque())
            window.append((now, event_id, str(value).lower()))
            self._forget_old(window, now, correlation)
            distinct = {v for _, _, v in window}
            if correlation.threshold(len(distinct)):
                return [e for _, e, _ in window], {"count": len(distinct)}
            return None

        # temporal / temporal_ordered: all referenced rules matched within the timespan
        seen = self._state.setdefault(key, {})
        for name in hit_names:
            seen[name] = (now, hits[name])
        for name in list(seen):
            if now - seen[name][0] > correlation.timespan:
                del seen[name]
        if any(name not in seen for name in correlation.rules):
            return None
        if correlation.type == "temporal_ordered":
            if correlation.rules[-1] not in hit_names:
                return None
            times = [seen[name][0] for name in correlation.rules]
            if any(earlier > later for earlier, later in zip(times, times[1:])):
                return None
        event_ids = list(dict.fromkeys(e for name in correlation.rules for e in seen[name][1]))
        return event_ids, {"count": len(event_ids)}

    @staticmethod
    def _forget_old(window: deque, now: datetime, correlation: CorrelationRule):
        while window and now - window[0][0] > correlation.timespan:
            window.popleft()
