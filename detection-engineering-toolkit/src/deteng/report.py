"""Console, Markdown, and JSON reports for lab-only detection runs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from deteng.models import Hit, Rule

LAB_BANNER = "LAB-ONLY / SYNTHETIC LOGS — personal educational portfolio, not official Defence material"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hit_record(hit: Hit) -> dict[str, Any]:
    return {
        "rule_id": hit.rule.id,
        "title": hit.rule.title,
        "severity": hit.rule.severity,
        "log_source": hit.rule.log_source,
        "description": hit.rule.description,
        "mitre": {
            "tactic": hit.rule.mitre.tactic,
            "technique_id": hit.rule.mitre.technique_id,
            "technique": hit.rule.mitre.technique,
        },
        "essential_eight": hit.rule.essential_eight,
        "ism": hit.rule.ism,
        "evidence_count": len(hit.events),
        "group": hit.group,
        "summary": hit.summary_fields(),
        "first_seen": hit.first_seen,
        "last_seen": hit.last_seen,
        "events": hit.events,
    }


def build_report(
    *,
    hits: list[Hit],
    rules: list[Rule],
    events: list[dict[str, Any]],
    logs_path: str,
    rules_dir: str,
) -> dict[str, Any]:
    return {
        "generated_at": _now_iso(),
        "lab_only": True,
        "synthetic_disclaimer": LAB_BANNER,
        "logs_path": logs_path,
        "rules_dir": rules_dir,
        "event_count": len(events),
        "rules_evaluated": len(rules),
        "hit_count": len(hits),
        "rules": [rule.id for rule in rules],
        "hits": [hit_record(hit) for hit in hits],
    }


def format_console(report: dict[str, Any]) -> str:
    lines = [
        "Detection Engineering Toolkit — Lab Report",
        "=" * 44,
        LAB_BANNER,
        "",
        f"Logs:    {report['logs_path']} ({report['event_count']} events)",
        f"Rules:   {report['rules_evaluated']} evaluated",
        f"Hits:    {report['hit_count']}",
        f"Generated (UTC): {report['generated_at']}",
        "",
    ]
    if not report["hits"]:
        lines.append("No detections. (Expected for clean / benign synthetic traffic.)")
        lines.append("")
        return "\n".join(lines)

    for item in report["hits"]:
        lines.append(f"[{item['severity'].upper()}] {item['rule_id']}  {item['title']}")
        lines.append(
            f"  MITRE: {item['mitre']['tactic']} / {item['mitre']['technique_id']} {item['mitre']['technique']}"
        )
        lines.append(f"  Essential Eight: {item['essential_eight']}")
        lines.append(f"  ISM: {item['ism']}")
        summary = ", ".join(f"{k}={v}" for k, v in item["summary"].items())
        lines.append(f"  Evidence: {item['evidence_count']} event(s)  {summary}")
        if item["first_seen"] or item["last_seen"]:
            lines.append(f"  First: {item['first_seen']}  Last: {item['last_seen']}")
        lines.append("")
    return "\n".join(lines)


def format_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Detection Engineering Toolkit — Lab Report",
        "",
        f"_{report['synthetic_disclaimer']}_",
        "",
        f"- Generated (UTC): `{report['generated_at']}`",
        f"- Logs: `{report['logs_path']}` ({report['event_count']} events)",
        f"- Rules evaluated: {report['rules_evaluated']}",
        f"- Hits: **{report['hit_count']}**",
        "",
    ]
    if not report["hits"]:
        lines.extend(
            [
                "No detections. This is the expected result for clean / benign synthetic traffic.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Rule | Title | ATT&CK | Essential Eight | Evidence |",
            "|----------|------|-------|--------|-----------------|----------|",
        ]
    )
    for item in report["hits"]:
        attack = f"{item['mitre']['technique_id']} {item['mitre']['technique']}"
        lines.append(
            f"| {item['severity']} | {item['rule_id']} | {item['title']} | {attack} | "
            f"{item['essential_eight']} | {item['evidence_count']} |"
        )
    lines.append("")
    for item in report["hits"]:
        lines.extend(
            [
                f"## {item['rule_id']} — {item['title']}",
                "",
                f"- **Severity:** {item['severity']}",
                f"- **Log source:** {item['log_source']}",
                f"- **MITRE:** {item['mitre']['tactic']} / {item['mitre']['technique_id']} {item['mitre']['technique']}",
                f"- **Essential Eight:** {item['essential_eight']}",
                f"- **ISM:** {item['ism']}",
                f"- **Window:** {item['first_seen']} → {item['last_seen']}",
                f"- **Evidence events:** {item['evidence_count']}",
                "",
                item["description"],
                "",
            ]
        )
    return "\n".join(lines)


def write_reports(report: dict[str, Any], out_dir: str | Path) -> tuple[Path, Path]:
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    json_path = dest / "detection-report.json"
    md_path = dest / "detection-report.md"
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(format_markdown(report), encoding="utf-8")
    return json_path, md_path
