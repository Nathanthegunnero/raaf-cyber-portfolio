"""Console, Markdown, and JSON reports for lab-only Essential Eight runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from e8check.models import Assessment, StrategyResult

LAB_BANNER = (
    "LAB-ONLY / SYNTHETIC EVIDENCE — personal educational portfolio, "
    "not official Defence material"
)
ROLLUP_NOTE = (
    "ACSC-style roll-up: overall maturity = minimum of the eight strategies "
    "(you are only as mature as your weakest strategy)"
)
NOT_AN_ASSESSMENT = (
    "Simplified lab model. This does not replace an ASD Essential Eight assessment."
)


def _ml_label(level: int) -> str:
    return f"ML{level}"


def result_record(result: StrategyResult) -> dict[str, Any]:
    return {
        "id": result.control.id,
        "strategy": result.control.strategy,
        "ism": result.control.ism,
        "maturity": result.maturity,
        "maturity_label": _ml_label(result.maturity),
        "notes": result.notes,
        "insufficient_evidence": result.insufficient_evidence,
        "description": result.control.description,
        "findings": [
            {
                "id": f"{finding.control_id}:{finding.field}:{finding.maturity}",
                "status": finding.status,
                "message": finding.message,
                "field": finding.field,
                "maturity": finding.maturity,
            }
            for finding in result.findings
        ],
    }


def build_report(assessment: Assessment) -> dict[str, Any]:
    evidence = assessment.evidence
    return {
        "generated_at": assessment.generated_at,
        "lab_only": True,
        "synthetic": evidence.synthetic,
        "synthetic_disclaimer": LAB_BANNER,
        "not_an_official_assessment": NOT_AN_ASSESSMENT,
        "rollup": ROLLUP_NOTE,
        "evidence_path": assessment.evidence_path,
        "host": evidence.host,
        "os": evidence.os,
        "collected_at": evidence.collected_at,
        "overall_maturity": assessment.overall,
        "overall_label": _ml_label(assessment.overall),
        "target": assessment.target,
        "gap_count": assessment.gap_count,
        "strategies": [result_record(item) for item in assessment.results],
    }


def format_console(report: dict[str, Any]) -> str:
    lines = [
        "Essential Eight Checker — Lab Report",
        "=" * 44,
        LAB_BANNER,
        NOT_AN_ASSESSMENT,
        "",
        f"Host:      {report['host']}",
        f"OS:        {report['os']}",
        f"Collected: {report['collected_at']}",
        f"Evidence:  {report['evidence_path']}",
        f"Synthetic: {'yes' if report['synthetic'] else 'no (unexpected for this lab tool)'}",
        f"Generated: {report['generated_at']} (UTC)",
        "",
        f"Overall maturity:  {_ml_label(report['overall_maturity'])}",
        f"  {ROLLUP_NOTE}",
        f"Target:            {_ml_label(report['target'])}",
        f"Gaps below target: {report['gap_count']}",
        "",
        f"{'ID':<7} {'Strategy':<42} {'ML':<4} {'ISM':<8} Notes",
        f"{'-' * 7} {'-' * 42} {'-' * 4} {'-' * 8} {'-' * 28}",
    ]
    for item in report["strategies"]:
        notes = item["notes"].replace("\n", " ")
        if len(notes) > 64:
            notes = notes[:61] + "..."
        lines.append(
            f"{item['id']:<7} {item['strategy']:<42} {item['maturity']:<4} {item['ism']:<8} {notes}"
        )
    lines.append("")
    lines.append("Findings")
    lines.append("--------")
    for item in report["strategies"]:
        for finding in item["findings"]:
            tag = finding["status"].upper()
            lines.append(f"[{tag}] {item['id']}  {finding['message']}")
    lines.append("")
    lines.append("Disclaimer: personal educational portfolio. Not official RAAF/ADF/ASD material.")
    lines.append("")
    return "\n".join(lines)


def format_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Essential Eight Checker — Lab Report",
        "",
        f"_{report['synthetic_disclaimer']}_",
        "",
        f"_{report['not_an_official_assessment']}_",
        "",
        f"- Generated (UTC): `{report['generated_at']}`",
        f"- Host: `{report['host']}` ({report['os']})",
        f"- Collected: `{report['collected_at']}`",
        f"- Evidence: `{report['evidence_path']}`",
        f"- Synthetic: `{report['synthetic']}`",
        f"- **Overall maturity: {_ml_label(report['overall_maturity'])}**",
        f"- Roll-up: {report['rollup']}",
        f"- Target: {_ml_label(report['target'])}",
        f"- Gaps below target: **{report['gap_count']}**",
        "",
        "| ID | Strategy | ML | ISM | Notes |",
        "|----|----------|----|-----|-------|",
    ]
    for item in report["strategies"]:
        notes = item["notes"].replace("|", "/")
        lines.append(
            f"| {item['id']} | {item['strategy']} | {item['maturity']} | {item['ism']} | {notes} |"
        )
    lines.append("")
    for item in report["strategies"]:
        lines.extend(
            [
                f"## {item['id']} — {item['strategy']}",
                "",
                f"- **Maturity:** {_ml_label(item['maturity'])}",
                f"- **ISM:** {item['ism']}",
                f"- **Insufficient evidence:** {item['insufficient_evidence']}",
                "",
                item["description"],
                "",
            ]
        )
        if item["findings"]:
            for finding in item["findings"]:
                lines.append(f"- [{finding['status'].upper()}] {finding['message']}")
            lines.append("")
    lines.extend(
        [
            "---",
            "",
            "Personal educational portfolio. Not official RAAF, ADF, or ASD material.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(report: dict[str, Any], out_dir: str | Path) -> tuple[Path, Path]:
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    json_path = dest / "e8-report.json"
    md_path = dest / "e8-report.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(format_markdown(report), encoding="utf-8")
    return json_path, md_path
