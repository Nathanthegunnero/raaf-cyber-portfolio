"""Engine tests: synthetic logs hit expected rules; clean logs hit none."""

from __future__ import annotations

from pathlib import Path

from deteng.engine import evaluate, evaluate_rule, parse_timestamp
from deteng.loader import load_logs, load_rules, parse_rule
from deteng.models import Condition, FieldCheck, Mitre, Rule, Sequence

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
SYNTHETIC = ROOT / "samples" / "synthetic_events.jsonl"
CLEAN = ROOT / "samples" / "clean_events.jsonl"

EXPECTED_IDS = {
    "DET-001",
    "DET-002",
    "DET-003",
    "DET-004",
    "DET-005",
    "DET-006",
    "DET-007",
    "DET-008",
}


def test_all_eight_rules_load():
    rules = load_rules(RULES_DIR)
    assert {rule.id for rule in rules} == EXPECTED_IDS
    for rule in rules:
        assert rule.severity in {"low", "medium", "high", "critical"}
        assert rule.ism in {"Detect", "Respond"}
        assert rule.mitre.technique_id.startswith("T")


def test_synthetic_triggers_all_rules():
    rules = load_rules(RULES_DIR)
    events = load_logs(SYNTHETIC)
    assert events, "synthetic log file should not be empty"
    assert all(event.get("synthetic") is True for event in events)
    hits = evaluate(rules, events)
    hit_ids = {hit.rule.id for hit in hits}
    missing = EXPECTED_IDS - hit_ids
    assert not missing, f"synthetic events missed rules: {sorted(missing)}"


def test_clean_triggers_no_rules():
    rules = load_rules(RULES_DIR)
    events = load_logs(CLEAN)
    assert events, "clean log file should not be empty"
    hits = evaluate(rules, events)
    assert hits == [], f"clean events unexpectedly hit {[h.rule.id for h in hits]}"


def test_failed_logon_threshold_requires_five():
    rules = {rule.id: rule for rule in load_rules(RULES_DIR)}
    rule = rules["DET-001"]
    base = {
        "timestamp": "2026-08-15T04:00:00Z",
        "host": "WS-LAB-99",
        "user": "lab.user",
        "action": "failed_logon",
        "synthetic": True,
    }
    four = [{**base, "timestamp": f"2026-08-15T04:00:0{i}Z"} for i in range(4)]
    assert evaluate_rule(rule, four) == []
    five = four + [{**base, "timestamp": "2026-08-15T04:00:09Z"}]
    hits = evaluate_rule(rule, five)
    assert len(hits) == 1
    assert hits[0].rule.id == "DET-001"
    assert len(hits[0].events) >= 5


def test_sequence_failed_then_success():
    """Optional sequence operator: failed logon then success, same user."""
    rule = Rule(
        id="DET-SEQ",
        title="Failed then success",
        description="Lab unit test for the sequence operator.",
        severity="medium",
        log_source="Security",
        condition=Condition(
            sequence=Sequence(
                first=(FieldCheck(field="action", equals="failed_logon"),),
                then=(FieldCheck(field="action", equals="success_logon"),),
                group_by=("user",),
                window_seconds=600,
            )
        ),
        mitre=Mitre(tactic="Credential Access", technique_id="T1110", technique="Brute Force"),
        essential_eight="Multi-factor Authentication",
        ism="Detect",
    )
    events = [
        {"timestamp": "2026-08-15T05:00:00Z", "user": "lab.user", "action": "failed_logon"},
        {"timestamp": "2026-08-15T05:02:00Z", "user": "lab.user", "action": "success_logon"},
    ]
    hits = evaluate_rule(rule, events)
    assert len(hits) == 1
    assert hits[0].group["user"] == "lab.user"

    too_late = [
        {"timestamp": "2026-08-15T05:00:00Z", "user": "lab.user", "action": "failed_logon"},
        {"timestamp": "2026-08-15T05:20:00Z", "user": "lab.user", "action": "success_logon"},
    ]
    assert evaluate_rule(rule, too_late) == []


def test_parse_timestamp_accepts_zulu():
    stamp = parse_timestamp("2026-08-15T01:00:00Z")
    assert stamp is not None
    assert stamp.year == 2026


def test_parse_rule_roundtrip_minimal():
    rule = parse_rule(
        {
            "id": "DET-TEST",
            "title": "Unit test rule",
            "description": "Not shipped; validates the loader.",
            "severity": "low",
            "log_source": "Security",
            "condition": {"all": [{"field": "action", "equals": "noop"}]},
            "mitre": {
                "tactic": "Discovery",
                "technique_id": "T1082",
                "technique": "System Information Discovery",
            },
            "essential_eight": "Application Control",
            "ism": "Detect",
        }
    )
    assert rule.id == "DET-TEST"
    assert rule.condition.all[0].equals == "noop"
