from __future__ import annotations

import argparse
import json
import sys

from analyzer.base import AnalyzeConfig, IamEntity, PolicyDoc, Statement
from analyzer.rules import run_all
from report import print_json, print_terminal, write_csv


def _parse_actions(val: list | str) -> list[str]:
    if isinstance(val, list):
        return val
    return [val] if val else []


def _parse_stmts(stmts: list[dict]) -> list[Statement]:
    return [
        Statement(
            effect=s.get("Effect", "Allow"),
            actions=_parse_actions(s.get("Action", [])),
            resources=_parse_actions(s.get("Resource", [])),
            conditions=s.get("Condition", {}),
        )
        for s in stmts
    ]


def _parse_entity(rec: dict) -> IamEntity:
    managed = [
        PolicyDoc(name=p["name"], statements=_parse_stmts(p.get("statements", [])))
        for p in rec.get("managed_policies", [])
    ]
    inline = [
        PolicyDoc(name=p["name"], statements=_parse_stmts(p.get("statements", [])), inline=True)
        for p in rec.get("inline_policies", [])
    ]
    return IamEntity(
        name=rec["name"],
        entity_type=rec.get("type", "user"),
        managed_policies=managed,
        inline_policies=inline,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-iam-analyzer",
        description="Analyze IAM policy documents for dangerous permissions patterns.",
    )
    p.add_argument(
        "input",
        nargs="?",
        default="-",
        help="JSON file with IAM entity records, or '-' for stdin (default: stdin)",
    )
    p.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum severity to report (default: LOW)",
    )
    p.add_argument("--output", choices=["terminal", "json"], default="terminal")
    p.add_argument("--csv-path", metavar="PATH", help="Also write CSV report to PATH")
    p.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit with code 2 if any CRITICAL finding is detected",
    )
    return p


def main() -> None:
    args = build_parser().parse_args()
    config = AnalyzeConfig(min_severity=args.min_severity)

    if args.input == "-":
        raw = json.load(sys.stdin)
    else:
        with open(args.input) as fh:
            raw = json.load(fh)

    entities = [_parse_entity(rec) for rec in raw]
    findings = run_all(entities, config)

    if args.output == "json":
        print_json(findings)
    else:
        print_terminal(findings)

    if args.csv_path:
        write_csv(findings, args.csv_path)

    if args.fail_on_critical and any(f.severity == "CRITICAL" for f in findings):
        sys.exit(2)


if __name__ == "__main__":
    main()
