"""Score a host evidence pack against Essential Eight controls.

Defensive only: this module reads fields already present in a lab evidence
pack. It does not scan hosts, generate payloads, or describe how to bypass
controls. Missing evidence is scored ML0 (conservative).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from e8check.models import (
    Assessment,
    Control,
    EvidencePack,
    FieldCheck,
    Finding,
    FindingSpec,
    StrategyResult,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_field(evidence: dict[str, Any], path: str) -> tuple[bool, Any]:
    """Return (found, value) for a dotted path into the evidence pack."""
    current: Any = evidence
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    if current is None:
        return False, None
    return True, current


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _as_num(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _values_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) and isinstance(right, bool):
        return left is right
    if isinstance(left, bool) or isinstance(right, bool):
        return _as_str(left).lower() == _as_str(right).lower()
    left_num = _as_num(left)
    right_num = _as_num(right)
    if left_num is not None and right_num is not None:
        return left_num == right_num
    return _as_str(left).lower() == _as_str(right).lower()


def check_field(evidence: dict[str, Any], check: FieldCheck) -> tuple[str, Any]:
    """Return (status, value) where status is pass / fail / missing."""
    found, value = get_field(evidence, check.field)
    if not found:
        return "missing", None
    if check.exists is True:
        return "pass", value
    if check.exists is False:
        return ("fail" if found else "pass"), value

    operators = (
        check.equals,
        check.not_equals,
        check.gte,
        check.lte,
        check.gt,
        check.lt,
    )
    if all(item is None for item in operators):
        return "pass", value

    if check.equals is not None and not _values_equal(value, check.equals):
        return "fail", value
    if check.not_equals is not None and _values_equal(value, check.not_equals):
        return "fail", value
    number = _as_num(value)
    if check.gte is not None and (number is None or number < float(check.gte)):
        return "fail", value
    if check.lte is not None and (number is None or number > float(check.lte)):
        return "fail", value
    if check.gt is not None and (number is None or number <= float(check.gt)):
        return "fail", value
    if check.lt is not None and (number is None or number >= float(check.lt)):
        return "fail", value
    return "pass", value


def referenced_fields(control: Control) -> list[str]:
    fields: list[str] = []
    for rule in control.maturity_rules:
        for check in rule.checks:
            if check.field not in fields:
                fields.append(check.field)
    return fields


def _rule_for_level(control: Control, level: int):
    for rule in control.maturity_rules:
        if rule.level == level:
            return rule
    return None


def _finding_from_spec(control: Control, spec: FindingSpec, evidence: dict[str, Any]) -> Finding:
    proxy = FieldCheck(
        field=spec.field,
        equals=spec.equals,
        not_equals=spec.not_equals,
        gte=spec.gte,
        lte=spec.lte,
        gt=spec.gt,
        lt=spec.lt,
    )
    status, _value = check_field(evidence, proxy)
    if status == "missing":
        result_status = "fail" if spec.maturity <= 1 else "gap"
        return Finding(
            control_id=control.id,
            strategy=control.strategy,
            status=result_status,
            message=f"insufficient evidence: {spec.field}",
            field=spec.field,
            maturity=spec.maturity,
        )
    if status == "pass":
        return Finding(
            control_id=control.id,
            strategy=control.strategy,
            status="pass",
            message=spec.pass_message or f"{spec.field} meets the check",
            field=spec.field,
            maturity=spec.maturity,
        )
    result_status = "fail" if spec.maturity <= 1 else "gap"
    return Finding(
        control_id=control.id,
        strategy=control.strategy,
        status=result_status,
        message=spec.fail_message or f"{spec.field} does not meet the check",
        field=spec.field,
        maturity=spec.maturity,
    )


def _notes(maturity: int, findings: list[Finding], insufficient: bool) -> str:
    if insufficient:
        return "insufficient evidence"
    gaps = [item.message for item in findings if item.status in {"fail", "gap"}]
    if maturity == 3 and not gaps:
        return "meets ML3"
    if gaps:
        return "; ".join(gaps[:2])
    return f"meets ML{maturity}"


def evaluate_control(control: Control, evidence: dict[str, Any]) -> StrategyResult:
    """Assign maturity 0–3. Missing required evidence → ML0."""
    findings = [_finding_from_spec(control, spec, evidence) for spec in control.findings]

    section = control.evidence_section
    section_found, section_value = get_field(evidence, section)
    if not section_found or not isinstance(section_value, dict):
        extra = Finding(
            control_id=control.id,
            strategy=control.strategy,
            status="fail",
            message=f"insufficient evidence: missing section '{section}'",
            field=section,
            maturity=1,
        )
        return StrategyResult(
            control=control,
            maturity=0,
            findings=[extra, *findings],
            notes="insufficient evidence",
            insufficient_evidence=True,
        )

    missing = [name for name in referenced_fields(control) if not get_field(evidence, name)[0]]
    if missing:
        extra = Finding(
            control_id=control.id,
            strategy=control.strategy,
            status="fail",
            message=f"insufficient evidence: {', '.join(missing)}",
            field=missing[0],
            maturity=1,
        )
        return StrategyResult(
            control=control,
            maturity=0,
            findings=[extra, *findings],
            notes="insufficient evidence",
            insufficient_evidence=True,
        )

    maturity = 0
    for level in (1, 2, 3):
        rule = _rule_for_level(control, level)
        if rule is None:
            break
        if any(check_field(evidence, check)[0] != "pass" for check in rule.checks):
            break
        maturity = level

    return StrategyResult(
        control=control,
        maturity=maturity,
        findings=findings,
        notes=_notes(maturity, findings, insufficient=False),
        insufficient_evidence=False,
    )


def overall_maturity(scores: list[int]) -> int:
    """ACSC-style roll-up: overall = minimum of the eight strategies."""
    if not scores:
        return 0
    return min(scores)


def assess(
    controls: list[Control],
    evidence: EvidencePack,
    *,
    target: int = 1,
    generated_at: str | None = None,
) -> Assessment:
    results = [evaluate_control(control, evidence.raw) for control in controls]
    results.sort(key=lambda item: item.control.id)
    overall = overall_maturity([item.maturity for item in results])
    gap_count = sum(1 for item in results if item.maturity < target)
    return Assessment(
        evidence=evidence,
        results=results,
        overall=overall,
        target=target,
        gap_count=gap_count,
        evidence_path=evidence.path,
        generated_at=generated_at or _now_iso(),
    )
