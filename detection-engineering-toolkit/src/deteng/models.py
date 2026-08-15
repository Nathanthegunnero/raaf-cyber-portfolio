"""Typed rule and hit models for the lab-only detection engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
ISM_FUNCTIONS = ("Detect", "Respond")
SEVERITY_ORDER = {name: idx for idx, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Mitre:
    tactic: str
    technique_id: str
    technique: str


@dataclass(frozen=True)
class FieldCheck:
    """A single field predicate: equals / contains / regex / numeric compare."""

    field: str
    equals: Any = None
    contains: str | None = None
    regex: str | None = None
    gte: float | None = None
    lte: float | None = None
    gt: float | None = None
    lt: float | None = None


@dataclass(frozen=True)
class Threshold:
    count: int
    window_seconds: int
    group_by: tuple[str, ...] = ()


@dataclass(frozen=True)
class Sequence:
    """Ordered pair: a 'first' match followed by a 'then' match, same group."""

    first: tuple[FieldCheck, ...]
    then: tuple[FieldCheck, ...]
    group_by: tuple[str, ...] = ()
    window_seconds: int = 600


@dataclass(frozen=True)
class Condition:
    all: tuple[FieldCheck, ...] = ()
    any: tuple[FieldCheck, ...] = ()
    threshold: Threshold | None = None
    sequence: Sequence | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: str
    log_source: str
    condition: Condition
    mitre: Mitre
    essential_eight: str
    ism: str
    path: str = ""


@dataclass
class Hit:
    rule: Rule
    events: list[dict[str, Any]]
    group: dict[str, str] = field(default_factory=dict)

    @property
    def first_seen(self) -> str:
        stamps = [str(e.get("timestamp", "")) for e in self.events if e.get("timestamp")]
        return min(stamps) if stamps else ""

    @property
    def last_seen(self) -> str:
        stamps = [str(e.get("timestamp", "")) for e in self.events if e.get("timestamp")]
        return max(stamps) if stamps else ""

    def summary_fields(self) -> dict[str, str]:
        """Compact evidence labels for console / markdown reports."""
        out: dict[str, str] = dict(self.group)
        if self.events:
            first = self.events[0]
            for key in ("user", "host", "src_ip", "dest_ip", "dest_port", "process"):
                if key not in out and first.get(key) not in (None, ""):
                    out[key] = str(first[key])
        return out
