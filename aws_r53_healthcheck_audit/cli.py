"""Command line entry point."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .collect import collect
from .model import Inventory
from .report import render
from .rules import ALL_RULES, evaluate, should_fail

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-r53-healthcheck-audit",
        description=(
            "Join Route 53 health checks to the record sets and CloudWatch alarms that "
            "reference them, and report both directions of the mismatch."
        ),
        epilog="Rules: " + ", ".join(ALL_RULES),
    )
    parser.add_argument("--profile", help="AWS profile to use")
    parser.add_argument(
        "--zone",
        action="append",
        dest="zones",
        metavar="ZONE_ID",
        help="limit record scanning to this hosted zone id (repeatable)",
    )
    parser.add_argument(
        "--alarm-region",
        default="us-east-1",
        help="region to read CloudWatch alarms from (default: us-east-1, where Route 53 "
        "publishes HealthCheckStatus)",
    )
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "never"),
        default="medium",
        help="lowest severity that exits 1 (default: medium)",
    )
    parser.add_argument(
        "--ignore",
        default="",
        metavar="RULE,RULE",
        help="comma-separated rules to drop from output and exit code",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _inventory(args) -> Inventory:
    import boto3

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    return collect(
        route53=session.client("route53"),
        cloudwatch=session.client("cloudwatch", region_name=args.alarm_region),
        zone_ids=args.zones,
        alarm_region=args.alarm_region,
    )


def main(argv: list[str] | None = None, collector=_inventory) -> int:
    args = build_parser().parse_args(argv)
    ignore = {part for part in args.ignore.split(",") if part.strip()}
    unknown = {r.strip().upper() for r in ignore} - set(ALL_RULES)
    if unknown:
        print(f"unknown rule(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return EXIT_ERROR

    try:
        inventory = collector(args)
    except Exception as exc:  # AWS API, credential and profile errors all land here
        if type(exc).__module__.split(".")[0] not in ("botocore", "boto3"):
            raise
        print(f"aws error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = evaluate(inventory, ignore=ignore)
    print(render(findings, args.format))
    return EXIT_FINDINGS if should_fail(findings, args.fail_on) else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
