"""CLI tests: list-rules, run, and report against lab samples."""

from __future__ import annotations

from pathlib import Path

from deteng.cli import main

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
SYNTHETIC = ROOT / "samples" / "synthetic_events.jsonl"
CLEAN = ROOT / "samples" / "clean_events.jsonl"

EXPECTED_IDS = [
    "DET-001",
    "DET-002",
    "DET-003",
    "DET-004",
    "DET-005",
    "DET-006",
    "DET-007",
    "DET-008",
]


def test_list_rules_returns_all_ids(capsys):
    rc = main(["list-rules", "--rules", str(RULES_DIR)])
    assert rc == 0
    out = capsys.readouterr().out
    for rule_id in EXPECTED_IDS:
        assert rule_id in out
    assert "8 rules" in out


def test_run_synthetic_prints_hits(capsys):
    rc = main(["run", "--logs", str(SYNTHETIC), "--rules", str(RULES_DIR)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Hits:" in out
    for rule_id in EXPECTED_IDS:
        assert rule_id in out
    assert "LAB-ONLY" in out


def test_run_clean_prints_no_detections(capsys):
    rc = main(["run", "--logs", str(CLEAN), "--rules", str(RULES_DIR)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "No detections" in out
    assert "Hits:    0" in out


def test_report_writes_json_and_markdown(tmp_path, capsys):
    rc = main(
        [
            "report",
            "--logs",
            str(SYNTHETIC),
            "--rules",
            str(RULES_DIR),
            "--out",
            str(tmp_path),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    json_path = tmp_path / "detection-report.json"
    md_path = tmp_path / "detection-report.md"
    assert json_path.is_file()
    assert md_path.is_file()
    assert str(json_path) in out
    text = json_path.read_text(encoding="utf-8")
    assert "DET-001" in text
    assert "lab_only" in text


def test_run_missing_logs_exits_2(tmp_path, capsys):
    rc = main(["run", "--logs", str(tmp_path / "missing.jsonl"), "--rules", str(RULES_DIR)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found" in err
