"""CLI tests: list-controls, run, report, and missing-file exit code."""

from __future__ import annotations

from pathlib import Path

from e8check.cli import main

ROOT = Path(__file__).resolve().parents[1]
CONTROLS_DIR = ROOT / "controls"
LAB_ML1 = ROOT / "samples" / "lab_ml1.json"
LAB_GAPS = ROOT / "samples" / "lab_gaps.json"

EXPECTED_IDS = [
    "E8-01",
    "E8-02",
    "E8-03",
    "E8-04",
    "E8-05",
    "E8-06",
    "E8-07",
    "E8-08",
]


def test_list_controls_prints_e8_01_to_e8_08(capsys):
    rc = main(["list-controls", "--controls", str(CONTROLS_DIR)])
    assert rc == 0
    out = capsys.readouterr().out
    for control_id in EXPECTED_IDS:
        assert control_id in out
    assert "8 controls" in out


def test_run_lab_ml1_prints_report(capsys):
    rc = main(
        [
            "run",
            "--evidence",
            str(LAB_ML1),
            "--controls",
            str(CONTROLS_DIR),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Overall maturity" in out
    assert "WS-LAB-E8-01" in out
    assert "LAB-ONLY" in out
    for control_id in EXPECTED_IDS:
        assert control_id in out


def test_run_lab_gaps_overall_ml0(capsys):
    rc = main(
        [
            "run",
            "--evidence",
            str(LAB_GAPS),
            "--controls",
            str(CONTROLS_DIR),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Overall maturity:  ML0" in out
    assert "WS-LAB-E8-GAPS" in out


def test_report_writes_json_and_markdown(tmp_path, capsys):
    rc = main(
        [
            "report",
            "--evidence",
            str(LAB_ML1),
            "--controls",
            str(CONTROLS_DIR),
            "--out",
            str(tmp_path),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    json_path = tmp_path / "e8-report.json"
    md_path = tmp_path / "e8-report.md"
    assert json_path.is_file()
    assert md_path.is_file()
    assert str(json_path) in out
    text = json_path.read_text(encoding="utf-8")
    assert "E8-01" in text
    assert "lab_only" in text
    assert "overall_maturity" in text
    md = md_path.read_text(encoding="utf-8")
    assert "Essential Eight" in md


def test_run_missing_evidence_exits_2(tmp_path, capsys):
    rc = main(
        [
            "run",
            "--evidence",
            str(tmp_path / "missing.json"),
            "--controls",
            str(CONTROLS_DIR),
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found" in err
