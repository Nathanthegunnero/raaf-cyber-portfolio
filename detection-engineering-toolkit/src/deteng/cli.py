"""Command-line interface for the lab-only detection engineering toolkit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from deteng import __version__
from deteng.engine import evaluate
from deteng.loader import LoadError, load_logs, load_rules
from deteng.models import SEVERITY_ORDER
from deteng.report import build_report, format_console, write_reports

DEFAULT_LOGS = Path("samples/synthetic_events.jsonl")
DEFAULT_RULES = Path("rules")
DEFAULT_OUT = Path("out")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deteng",
        description=(
            "Lab-only detection engineering toolkit. Evaluates YAML rules against "
            "synthetic logs and maps hits to MITRE ATT&CK, the ASD Essential Eight, "
            "and ISM Detect/Respond. Personal educational use. Not official Defence material."
        ),
    )
    parser.add_argument("--version", action="version", version=f"deteng {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Evaluate rules, print a console report, optionally write files")
    run.add_argument("--logs", type=Path, default=DEFAULT_LOGS, help="JSONL / JSON / key=value log file")
    run.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Directory of YAML rules")
    run.add_argument("--out", type=Path, default=None, help="If set, write detection-report.json and .md")

    listed = sub.add_parser("list-rules", help="List loaded detection rule IDs")
    listed.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Directory of YAML rules")

    report = sub.add_parser("report", help="Same as run, but always writes JSON + Markdown (default ./out)")
    report.add_argument("--logs", type=Path, default=DEFAULT_LOGS, help="JSONL / JSON / key=value log file")
    report.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Directory of YAML rules")
    report.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Output directory (default: ./out)")
    return parser


def _print_rules(rules_dir: Path) -> int:
    rules = load_rules(rules_dir)
    rules = sorted(rules, key=lambda rule: (-SEVERITY_ORDER.get(rule.severity, 0), rule.id))
    width = max(len(rule.id) for rule in rules)
    print(f"{'ID':<{width}}  {'SEV':<8}  TITLE")
    print(f"{'-' * width}  {'-' * 8}  {'-' * 24}")
    for rule in rules:
        print(f"{rule.id:<{width}}  {rule.severity:<8}  {rule.title}")
    print(f"\n{len(rules)} rules  (lab-only / synthetic)")
    return 0


def _run(logs: Path, rules_dir: Path, out: Path | None) -> int:
    rules = load_rules(rules_dir)
    events = load_logs(logs)
    hits = evaluate(rules, events)
    report = build_report(
        hits=hits,
        rules=rules,
        events=events,
        logs_path=str(logs),
        rules_dir=str(rules_dir),
    )
    print(format_console(report), end="")
    if out is not None:
        json_path, md_path = write_reports(report, out)
        print(f"Wrote {json_path}")
        print(f"Wrote {md_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "list-rules":
            return _print_rules(args.rules)
        if args.command == "run":
            return _run(args.logs, args.rules, args.out)
        if args.command == "report":
            return _run(args.logs, args.rules, args.out)
    except LoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
