"""Typed models for the lab-only Essential Eight checker."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

STRATEGIES = (
    "Application control",
    "Patch applications",
    "Patch operating systems",
    "Restrict administrative privileges",
    "Configure Microsoft Office macro settings",
    "User application hardening",
    "Multi-factor authentication",
    "Regular backups",
)

ISM_FUNCTIONS = ("Protect", "Detect")
MATURITY_LEVELS = (0, 1, 2, 3)


@dataclass(frozen=True)
class FieldCheck:
    field: str
    equals: Any = None
    not_equals: Any = None
    gte: float | None = None
    lte: float | None = None
    gt: float | None = None
    lt: float | None = None
    exists: bool | None = None
    reason: str = ""


@dataclass(frozen=True)
class LevelRule:
    level: int
    checks: tuple[FieldCheck, ...]


@dataclass(frozen=True)
class FindingSpec:
    id: str
    field: str
    equals: Any = None
    not_equals: Any = None
    gte: float | None = None
    lte: float | None = None
    gt: float | None = None
    lt: float | None = None
    pass_message: str = ""
    fail_message: str = ""
    maturity: int = 1


@dataclass(frozen=True)
class Control:
    id: str
    strategy: str
    description: str
    ism: str
    evidence_section: str
    maturity_rules: tuple[LevelRule, ...]
    findings: tuple[FindingSpec, ...]
    path: str = ""


@dataclass
class Finding:
    control_id: str
    strategy: str
    status: str
    message: str
    field: str = ""
    maturity: int = 1


@dataclass
class StrategyResult:
    control: Control
    maturity: int
    findings: list[Finding] = field(default_factory=list)
    notes: str = ""
    insufficient_evidence: bool = False


@dataclass
class EvidencePack:
    synthetic: bool
    host: str
    os: str
    collected_at: str
    raw: dict[str, Any]
    path: str = ""


@dataclass
class Assessment:
    evidence: EvidencePack
    results: list[StrategyResult]
    overall: int
    target: int
    gap_count: int
    evidence_path: str
    generated_at: str

    @property
    def strategies(self) -> list[StrategyResult]:
        return self.results
