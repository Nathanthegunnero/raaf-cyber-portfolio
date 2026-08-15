"""Load YAML Essential Eight controls and JSON host evidence packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from e8check.models import (
    ISM_FUNCTIONS,
    STRATEGIES,
    Control,
    EvidencePack,
    FieldCheck,
    FindingSpec,
    LevelRule,
)

REQUIRED_CONTROL_FIELDS = (
    "id",
    "strategy",
    "description",
    "ism",
    "evidence_section",
    "maturity_rules",
)

CHECK_KEYS = {
    "field",
    "equals",
    "not_equals",
    "gte",
    "lte",
    "gt",
    "lt",
    "exists",
    "reason",
}


class LoadError(ValueError):
    """Invalid control or evidence input."""


def _parse_check(raw: Any, source: str) -> FieldCheck:
    if not isinstance(raw, dict) or "field" not in raw:
        raise LoadError(f"{source}: each check needs a 'field' key, got {raw!r}")
    unknown = set(raw) - CHECK_KEYS
    if unknown:
        raise LoadError(f"{source}: unknown check keys {sorted(unknown)}")
    return FieldCheck(
        field=str(raw["field"]),
        equals=raw.get("equals"),
        not_equals=raw.get("not_equals"),
        gte=raw.get("gte"),
        lte=raw.get("lte"),
        gt=raw.get("gt"),
        lt=raw.get("lt"),
        exists=raw.get("exists"),
        reason=str(raw.get("reason") or ""),
    )


def _parse_checks(raw: Any, source: str) -> tuple[FieldCheck, ...]:
    if raw is None:
        return ()
    if isinstance(raw, dict):
        return (_parse_check(raw, source),)
    if not isinstance(raw, list):
        raise LoadError(f"{source}: expected a list of field checks")
    return tuple(_parse_check(item, source) for item in raw)


def _parse_maturity_rules(raw: Any, source: str) -> tuple[LevelRule, ...]:
    if not isinstance(raw, dict):
        raise LoadError(f"{source}: maturity_rules must be a mapping of level → checks")
    rules: list[LevelRule] = []
    for key, body in raw.items():
        try:
            level = int(key)
        except (TypeError, ValueError) as exc:
            raise LoadError(f"{source}: maturity level {key!r} is not an integer") from exc
        if level not in (1, 2, 3):
            raise LoadError(f"{source}: maturity level must be 1, 2, or 3 (got {level})")
        if not isinstance(body, dict):
            raise LoadError(f"{source}: maturity_rules.{level} must be a mapping")
        checks = _parse_checks(body.get("all"), f"{source}.maturity_rules.{level}.all")
        if not checks:
            raise LoadError(f"{source}: maturity_rules.{level} needs a non-empty 'all' list")
        rules.append(LevelRule(level=level, checks=checks))
    rules.sort(key=lambda item: item.level)
    return tuple(rules)


def _parse_finding(raw: Any, source: str) -> FindingSpec:
    if not isinstance(raw, dict) or "id" not in raw or "field" not in raw:
        raise LoadError(f"{source}: finding needs id and field")
    try:
        maturity = int(raw.get("maturity", 1))
    except (TypeError, ValueError) as exc:
        raise LoadError(f"{source}: finding maturity must be an integer") from exc
    return FindingSpec(
        id=str(raw["id"]),
        field=str(raw["field"]),
        equals=raw.get("equals"),
        not_equals=raw.get("not_equals"),
        gte=raw.get("gte"),
        lte=raw.get("lte"),
        gt=raw.get("gt"),
        lt=raw.get("lt"),
        pass_message=str(raw.get("pass") or raw.get("pass_message") or ""),
        fail_message=str(raw.get("fail") or raw.get("fail_message") or ""),
        maturity=maturity,
    )


def parse_control(raw: dict[str, Any], source: str = "<memory>") -> Control:
    if not isinstance(raw, dict):
        raise LoadError(f"{source}: control document must be a mapping")
    missing = [key for key in REQUIRED_CONTROL_FIELDS if key not in raw]
    if missing:
        raise LoadError(f"{source}: missing fields {missing}")
    strategy = str(raw["strategy"])
    if strategy not in STRATEGIES:
        raise LoadError(f"{source}: strategy must be an official Essential Eight name")
    ism = str(raw["ism"])
    if ism not in ISM_FUNCTIONS:
        raise LoadError(f"{source}: ism must be Protect or Detect")
    findings_raw = raw.get("findings") or []
    if not isinstance(findings_raw, list):
        raise LoadError(f"{source}: findings must be a list")
    return Control(
        id=str(raw["id"]),
        strategy=strategy,
        description=str(raw["description"]).strip(),
        ism=ism,
        evidence_section=str(raw["evidence_section"]),
        maturity_rules=_parse_maturity_rules(raw["maturity_rules"], source),
        findings=tuple(
            _parse_finding(item, f"{source}.findings[{index}]")
            for index, item in enumerate(findings_raw)
        ),
        path=source,
    )


def load_controls(controls_dir: str | Path) -> list[Control]:
    path = Path(controls_dir)
    if not path.is_dir():
        raise LoadError(f"controls directory not found: {path}")
    files = sorted(list(path.glob("*.yaml")) + list(path.glob("*.yml")))
    if not files:
        raise LoadError(f"no YAML controls in {path}")
    controls: list[Control] = []
    seen: set[str] = set()
    for file in files:
        payload = yaml.safe_load(file.read_text(encoding="utf-8"))
        if payload is None:
            raise LoadError(f"{file}: empty document")
        control = parse_control(payload, str(file))
        if control.id in seen:
            raise LoadError(f"{file}: duplicate control id {control.id}")
        seen.add(control.id)
        controls.append(control)
    controls.sort(key=lambda item: item.id)
    return controls


def load_evidence(evidence_path: str | Path) -> EvidencePack:
    path = Path(evidence_path)
    if not path.is_file():
        raise LoadError(f"evidence file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise LoadError(f"{path}: invalid JSON ({exc})") from exc
    if not isinstance(raw, dict):
        raise LoadError(f"{path}: evidence root must be a JSON object")
    return EvidencePack(
        synthetic=bool(raw.get("synthetic", False)),
        host=str(raw.get("host") or "UNKNOWN"),
        os=str(raw.get("os") or "UNKNOWN"),
        collected_at=str(raw.get("collected_at") or ""),
        raw=raw,
        path=str(path),
    )
