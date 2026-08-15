"""Evaluate YAML detection rules against synthetic lab events.

Defensive only: this module matches field evidence already present in logs.
It does not generate payloads, encode commands, or describe attack procedures.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from deteng.models import (
    SEVERITY_ORDER,
    Condition,
    FieldCheck,
    Hit,
    Rule,
    Sequence,
    Threshold,
)


def parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _as_num(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def check_field(event: dict[str, Any], check: FieldCheck) -> bool:
    raw = event.get(check.field)
    operators = (
        check.equals,
        check.contains,
        check.regex,
        check.gte,
        check.lte,
        check.gt,
        check.lt,
    )
    if all(item is None for item in operators):
        return raw is not None

    if check.equals is not None:
        if _as_str(raw).lower() != _as_str(check.equals).lower():
            return False
    if check.contains is not None:
        if _as_str(check.contains).lower() not in _as_str(raw).lower():
            return False
    if check.regex is not None:
        if raw is None or re.search(check.regex, _as_str(raw)) is None:
            return False
    number = _as_num(raw)
    if check.gte is not None and (number is None or number < float(check.gte)):
        return False
    if check.lte is not None and (number is None or number > float(check.lte)):
        return False
    if check.gt is not None and (number is None or number <= float(check.gt)):
        return False
    if check.lt is not None and (number is None or number >= float(check.lt)):
        return False
    return True


def matches_checks(event: dict[str, Any], checks: tuple[FieldCheck, ...], mode: str) -> bool:
    if not checks:
        return True
    results = [check_field(event, check) for check in checks]
    return all(results) if mode == "all" else any(results)


def matches_fields(event: dict[str, Any], condition: Condition) -> bool:
    if condition.all and not matches_checks(event, condition.all, "all"):
        return False
    if condition.any and not matches_checks(event, condition.any, "any"):
        return False
    return True


def _group_key(event: dict[str, Any], fields: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(_as_str(event.get(name, "")) for name in fields)


def _group_dict(fields: tuple[str, ...], key: tuple[str, ...]) -> dict[str, str]:
    return {name: value for name, value in zip(fields, key) if name}


def evaluate_threshold(rule: Rule, events: list[dict[str, Any]], threshold: Threshold) -> list[Hit]:
    buckets: dict[tuple[str, ...], list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
    for event in events:
        stamp = parse_timestamp(event.get("timestamp"))
        if stamp is None:
            continue
        buckets[_group_key(event, threshold.group_by)].append((stamp, event))

    hits: list[Hit] = []
    window = timedelta(seconds=threshold.window_seconds)
    for key, items in buckets.items():
        items.sort(key=lambda pair: pair[0])
        left = 0
        for right, (stamp, _) in enumerate(items):
            while items[left][0] < stamp - window:
                left += 1
            if right - left + 1 >= threshold.count:
                evidence = [event for _, event in items[left : right + 1]]
                hits.append(Hit(rule=rule, events=evidence, group=_group_dict(threshold.group_by, key)))
                break
    return hits


def evaluate_sequence(rule: Rule, events: list[dict[str, Any]], sequence: Sequence) -> list[Hit]:
    firsts: dict[tuple[str, ...], list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
    thens: dict[tuple[str, ...], list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
    for event in events:
        stamp = parse_timestamp(event.get("timestamp"))
        if stamp is None:
            continue
        key = _group_key(event, sequence.group_by)
        if matches_checks(event, sequence.first, "all"):
            firsts[key].append((stamp, event))
        if matches_checks(event, sequence.then, "all"):
            thens[key].append((stamp, event))

    hits: list[Hit] = []
    window = timedelta(seconds=sequence.window_seconds)
    for key, first_items in firsts.items():
        later = thens.get(key, [])
        if not later:
            continue
        first_items.sort(key=lambda pair: pair[0])
        later.sort(key=lambda pair: pair[0])
        found = False
        for first_stamp, first_event in first_items:
            for then_stamp, then_event in later:
                if first_stamp < then_stamp <= first_stamp + window:
                    hits.append(
                        Hit(
                            rule=rule,
                            events=[first_event, then_event],
                            group=_group_dict(sequence.group_by, key),
                        )
                    )
                    found = True
                    break
            if found:
                break
    return hits


def evaluate_rule(rule: Rule, events: list[dict[str, Any]]) -> list[Hit]:
    condition = rule.condition
    if condition.sequence is not None:
        scoped = [event for event in events if matches_fields(event, condition)]
        return evaluate_sequence(rule, scoped, condition.sequence)

    matched = [event for event in events if matches_fields(event, condition)]
    if condition.threshold is not None:
        return evaluate_threshold(rule, matched, condition.threshold)
    if not matched:
        return []
    return [Hit(rule=rule, events=matched)]


def evaluate(rules: list[Rule], events: list[dict[str, Any]]) -> list[Hit]:
    hits: list[Hit] = []
    for rule in rules:
        hits.extend(evaluate_rule(rule, events))
    hits.sort(key=lambda hit: (-SEVERITY_ORDER.get(hit.rule.severity, 0), hit.rule.id))
    return hits
