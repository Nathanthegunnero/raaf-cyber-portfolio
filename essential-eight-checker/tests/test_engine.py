"""Engine tests: lab_ml1 scores >= ML1; lab_gaps scores ML0; overall is min."""

from __future__ import annotations

import copy
from pathlib import Path

from e8check.engine import assess, evaluate_control, overall_maturity
from e8check.loader import load_controls, load_evidence

ROOT = Path(__file__).resolve().parents[1]
CONTROLS_DIR = ROOT / "controls"
LAB_ML1 = ROOT / "samples" / "lab_ml1.json"
LAB_GAPS = ROOT / "samples" / "lab_gaps.json"

EXPECTED_IDS = {
    "E8-01",
    "E8-02",
    "E8-03",
    "E8-04",
    "E8-05",
    "E8-06",
    "E8-07",
    "E8-08",
}


def test_all_eight_controls_load():
    controls = load_controls(CONTROLS_DIR)
    assert {item.id for item in controls} == EXPECTED_IDS
    for item in controls:
        assert item.ism in {"Protect", "Detect"}
        assert item.strategy
        assert item.maturity_rules


def test_lab_ml1_overall_at_least_one_and_no_none():
    controls = load_controls(CONTROLS_DIR)
    pack = load_evidence(LAB_ML1)
    assert pack.synthetic is True
    assessment = assess(controls, pack, target=1)
    assert assessment.overall >= 1
    assert len(assessment.results) == 8
    for result in assessment.results:
        assert result.maturity is not None
        assert result.maturity in (0, 1, 2, 3)
        assert result.control.id in EXPECTED_IDS
    assert assessment.overall == min(item.maturity for item in assessment.results)


def test_lab_gaps_overall_zero():
    controls = load_controls(CONTROLS_DIR)
    pack = load_evidence(LAB_GAPS)
    assert pack.synthetic is True
    assessment = assess(controls, pack, target=1)
    assert assessment.overall == 0
    assert assessment.gap_count == 8


def test_overall_is_minimum_constructed_pack():
    """Overall equals the weakest strategy: one strategy forced to ML0."""
    controls = load_controls(CONTROLS_DIR)
    pack = load_evidence(LAB_ML1)
    mutated = copy.deepcopy(pack.raw)
    mutated["backups"]["enabled"] = False
    pack.raw = mutated
    assessment = assess(controls, pack, target=1)
    scores = [item.maturity for item in assessment.results]
    assert assessment.overall == 0
    assert assessment.overall == min(scores)
    backups = next(item for item in assessment.results if item.control.id == "E8-08")
    assert backups.maturity == 0
    others = [item for item in assessment.results if item.control.id != "E8-08"]
    assert all(item.maturity >= 1 for item in others)


def test_overall_maturity_helper():
    assert overall_maturity([3, 2, 1, 3, 2, 1, 0, 2]) == 0
    assert overall_maturity([3, 2, 1, 3, 2, 1, 1, 2]) == 1
    assert overall_maturity([3, 3, 3, 3, 3, 3, 3, 3]) == 3
    assert overall_maturity([]) == 0


def test_missing_section_is_ml0_insufficient_evidence():
    controls = {item.id: item for item in load_controls(CONTROLS_DIR)}
    result = evaluate_control(controls["E8-07"], {"synthetic": True, "host": "WS-LAB-EMPTY"})
    assert result.maturity == 0
    assert result.insufficient_evidence is True
    assert "insufficient evidence" in result.notes
