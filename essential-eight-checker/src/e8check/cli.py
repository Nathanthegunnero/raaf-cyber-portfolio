"""Command-line interface for the lab-only Essential Eight checker."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from e8check import __version__
from e8check.engine import assess
from e8check.loader import LoadError, load_controls, load_evidence
from e8check.report import build_report, format_console, write_reports

DEFAULT_EVIDENCE = Path("samples/lab_ml1.json")
DEFAULT_CONTROLS = Path("controls")
DEFAULT_OUT = Path("out")
DEFAULT_TARGET = 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="e8check",
        description=(
            "Lab-only Essential Eight checker. Scores a synthetic host evidence "
            "pack against the eight public ACSC strategies (maturity 0–3; overall "
            "= minimum). Personal educational use. Not official Defence material."
        ),
    )
    parser.add_argument("--version", action="version", version=f"e8check {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Evaluate one evidence pack and print a console report")
    run.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE, help="JSON host evidence pack")
    run.add_argument("--controls", type=Path, default=DEFAULT_CONTROLS, help="Directory of YAML controls")
    run.add_argument("--out", type=Path, default=None, help="If set, write e8-report.json and e8-report.md")
    run.add_argument("--target", type=int, default=DEFAULT_TARGET, help="Gap threshold (default: 1)")

    listed = sub.add_parser("list-controls", help="List loaded Essential Eight control IDs")
    listed.add_argument("--controls", type=Path, default=DEFAULT_CONTROLS, help="Directory of YAML controls")

    report = sub.add_parser("report", help="Same as run, but always writes JSON + Markdown (default ./out)")
    report.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE, help="JSON host evidence pack")
    report.add_argument("--controls", type=Path, default=DEFAULT_CONTROLS, help="Directory of YAML controls")
    report.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Output directory (default: ./out)")
    report.add_argument("--target", type=int, default=DEFAULT_TARGET, help="Gap threshold (default: 1)")
    return parser


def _print_controls(controls_dir: Path) -> int:
    controls = load_controls(controls_dir)
    width = max(len(item.id) for item in controls)
    print(f"{'ID':<{width}}  {'ISM':<8}  STRATEGY")
    print(f"{'-' * width}  {'-' * 8}  {'-' * 24}")
    for item in controls:
        print(f"{item.id:<{width}}  {item.ism:<8}  {item.strategy}")
    print(f"\n{len(controls)} controls  (lab-only / simplified maturity model)")
    return 0


def _run(evidence: Path, controls_dir: Path, out: Path | None, target: int) -> int:
    if target not in (0, 1, 2, 3):
        print("error: --target must be 0, 1, 2, or 3", file=sys.stderr)
        return 2
    controls = load_controls(controls_dir)
    pack = load_evidence(evidence)
    assessment = assess(controls, pack, target=target)
    report = build_report(assessment)
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
        if args.command == "list-controls":
            return _print_controls(args.controls)
        if args.command == "run":
            return _run(args.evidence, args.controls, args.out, args.target)
        if args.command == "report":
            return _run(args.evidence, args.controls, args.out, args.target)
    except LoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
