"""Load YAML detection rules and JSON/JSONL/text synthetic logs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from deteng.models import (
    ISM_FUNCTIONS,
    SEVERITIES,
    Condition,
    FieldCheck,
    Mitre,
    Rule,
    Sequence,
    Threshold,
)

REQUIRED_RULE_FIELDS = (
    "id",
    "title",
    "description",
    "severity",
    "log_source",
    "condition",
    "mitre",
    "essential_eight",
    "ism",
)


class LoadError(ValueError):
    """Invalid rule or log input."""


def _as_tuple(value: Any) -> tuple:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def _parse_check(raw: Any, source: str) -> FieldCheck:
    if not isinstance(raw, dict) or "field" not in raw:
        raise LoadError(f"{source}: each check needs a 'field' key, got {raw!r}")
    unknown = set(raw) - {
        "field",
        "equals",
        "contains",
        "regex",
        "gte",
        "lte",
        "gt",
        "lt",
    }
    if unknown:
        raise LoadError(f"{source}: unknown check keys {sorted(unknown)}")
    return FieldCheck(
        field=str(raw["field"]),
        equals=raw.get("equals"),
        contains=raw.get("contains"),
        regex=raw.get("regex"),
        gte=raw.get("gte"),
        lte=raw.get("lte"),
        gt=raw.get("gt"),
        lt=raw.get("lt"),
    )


def _parse_checks(raw: Any, source: str) -> tuple[FieldCheck, ...]:
    if raw is None:
        return ()
    if isinstance(raw, dict):
        return (_parse_check(raw, source),)
    if not isinstance(raw, list):
        raise LoadError(f"{source}: expected a list of field checks")
    return tuple(_parse_check(item, source) for item in raw)


def _parse_threshold(raw: Any, source: str) -> Threshold | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise LoadError(f"{source}: threshold must be a mapping")
    try:
        count = int(raw["count"])
        window = int(raw["window_seconds"])
    except (KeyError, TypeError, ValueError) as exc:
        raise LoadError(f"{source}: threshold needs integer count and window_seconds") from exc
    if count < 1 or window < 1:
        raise LoadError(f"{source}: threshold count and window_seconds must be >= 1")
    group_by = tuple(str(g) for g in _as_tuple(raw.get("group_by")))
    return Threshold(count=count, window_seconds=window, group_by=group_by)


def _parse_sequence(raw: Any, source: str) -> Sequence | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise LoadError(f"{source}: sequence must be a mapping")
    first = _parse_checks(raw.get("first"), f"{source}.sequence.first")
    then = _parse_checks(raw.get("then"), f"{source}.sequence.then")
    if not first or not then:
        raise LoadError(f"{source}: sequence needs non-empty first and then checks")
    window = int(raw.get("window_seconds", 600))
    group_by = tuple(str(g) for g in _as_tuple(raw.get("group_by")))
    return Sequence(first=first, then=then, group_by=group_by, window_seconds=window)


def _parse_condition(raw: Any, source: str) -> Condition:
    if not isinstance(raw, dict):
        raise LoadError(f"{source}: condition must be a mapping")
    return Condition(
        all=_parse_checks(raw.get("all"), f"{source}.condition.all"),
        any=_parse_checks(raw.get("any"), f"{source}.condition.any"),
        threshold=_parse_threshold(raw.get("threshold"), f"{source}.condition"),
        sequence=_parse_sequence(raw.get("sequence"), f"{source}.condition"),
    )


def parse_rule(raw: dict[str, Any], source: str = "<memory>") -> Rule:
    missing = [key for key in REQUIRED_RULE_FIELDS if key not in raw]
    if missing:
        raise LoadError(f"{source}: missing fields {missing}")
    severity = str(raw["severity"]).lower()
    if severity not in SEVERITIES:
        raise LoadError(f"{source}: severity must be one of {SEVERITIES}")
    ism = str(raw["ism"])
    if ism not in ISM_FUNCTIONS:
        raise LoadError(f"{source}: ism must be Detect or Respond")
    mitre_raw = raw["mitre"]
    if not isinstance(mitre_raw, dict):
        raise LoadError(f"{source}: mitre must be a mapping")
    for key in ("tactic", "technique_id", "technique"):
        if key not in mitre_raw:
            raise LoadError(f"{source}: mitre missing {key}")
    return Rule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        description=str(raw["description"]),
        severity=severity,
        log_source=str(raw["log_source"]),
        condition=_parse_condition(raw["condition"], source),
        mitre=Mitre(
            tactic=str(mitre_raw["tactic"]),
            technique_id=str(mitre_raw["technique_id"]),
            technique=str(mitre_raw["technique"]),
        ),
        essential_eight=str(raw["essential_eight"]),
        ism=ism,
        path=source,
    )


def load_rules(rules_dir: str | Path) -> list[Rule]:
    """Load every ``*.yaml`` / ``*.yml`` file in ``rules_dir`` (one rule per file)."""
    path = Path(rules_dir)
    if not path.is_dir():
        raise LoadError(f"rules directory not found: {path}")
    files = sorted(list(path.glob("*.yaml")) + list(path.glob("*.yml")))
    if not files:
        raise LoadError(f"no YAML rules in {path}")
    rules: list[Rule] = []
    seen: set[str] = set()
    for file in files:
        payload = yaml.safe_load(file.read_text(encoding="utf-8"))
        if payload is None:
            raise LoadError(f"{file}: empty document")
        if isinstance(payload, list):
            documents = payload
        else:
            documents = [payload]
        for index, document in enumerate(documents):
            label = str(file) if len(documents) == 1 else f"{file}#{index}"
            rule = parse_rule(document, label)
            if rule.id in seen:
                raise LoadError(f"{label}: duplicate rule id {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
    return rules


def _parse_kv_line(line: str) -> dict[str, Any]:
    """Minimal key=value text log line (values may be quoted)."""
    event: dict[str, Any] = {}
    token = ""
    key = None
    in_quote = False
    for char in line.strip() + " ":
        if char == '"' and not in_quote:
            in_quote = True
            continue
        if char == '"' and in_quote:
            in_quote = False
            continue
        if char == "=" and key is None and not in_quote:
            key = token.strip()
            token = ""
            continue
        if char.isspace() and not in_quote:
            if key is not None:
                event[key] = token
            key = None
            token = ""
            continue
        token += char
    return event


def load_logs(logs_path: str | Path) -> list[dict[str, Any]]:
    """Load JSONL, a JSON array, or simple key=value text lines.

    Lines starting with ``#`` are comments. Blank lines are skipped.
    """
    path = Path(logs_path)
    if not path.is_file():
        raise LoadError(f"logs file not found: {path}")
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        data = json.loads(text)
        if not isinstance(data, list):
            raise LoadError(f"{path}: JSON root must be an array of events")
        return [item for item in data if isinstance(item, dict)]

    events: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if raw.startswith("{"):
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise LoadError(f"{path}:{line_no}: invalid JSON ({exc})") from exc
            if not isinstance(item, dict):
                raise LoadError(f"{path}:{line_no}: expected a JSON object")
            events.append(item)
            continue
        kv = _parse_kv_line(raw)
        if kv:
            events.append(kv)
    return events
