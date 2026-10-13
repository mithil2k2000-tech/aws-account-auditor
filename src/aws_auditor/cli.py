"""aws-audit: read-only security and cost audit of an AWS account.

  aws-audit                              # current region, all checks
  aws-audit --regions all --format markdown -o report.md
  aws-audit --fail-on high               # exit 1 if anything HIGH or worse

Exit codes: 0 nothing at or above --fail-on, 1 findings at or above it,
2 the audit itself couldn't run (no credentials, bad arguments).
"""

from __future__ import annotations

import argparse
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from . import __version__, report
from .checks import CHECKS, by_name, ec2
from .models import Severity
from .runner import enabled_regions, run_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-audit",
        description="Read-only audit of an AWS account for security and cost problems.",
    )
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument(
        "--regions",
        default="",
        help="comma-separated regions, or 'all' (default: the profile's region)",
    )
    parser.add_argument("--checks", default="", help="comma-separated check names (default: all)")
    parser.add_argument("--list-checks", action="store_true", help="list the checks and exit")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    parser.add_argument(
        "--min-severity", default="info", help="leave out findings below this severity"
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        help="exit 1 if any finding is at or above this severity (use 'none' to always exit 0)",
    )
    parser.add_argument(
        "--require-tag",
        action="append",
        default=None,
        metavar="KEY",
        help="tag every instance must have (repeatable; default: Project, Owner)",
    )
    parser.add_argument("--no-colour", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        for check in CHECKS:
            scope = "global" if check.global_service else "per region"
            print(f"{check.name:<26} {scope:<11} {check.description}")
        return 0

    try:
        checks = by_name([c for c in args.checks.split(",") if c])
        min_severity = Severity.parse(args.min_severity)
        fail_on = None if args.fail_on.lower() == "none" else Severity.parse(args.fail_on)
    except ValueError as err:
        print(f"aws-audit: {err}", file=sys.stderr)
        return 2

    if args.require_tag:
        ec2.REQUIRED_TAGS = tuple(args.require_tag)

    try:
        session = boto3.Session(profile_name=args.profile)
        if args.regions == "all":
            regions = enabled_regions(session)
        elif args.regions:
            regions = [r.strip() for r in args.regions.split(",") if r.strip()]
        else:
            regions = [session.region_name or "us-east-1"]
        result = run_audit(session, checks, regions)
    except NoCredentialsError:
        print(
            "aws-audit: no AWS credentials found (try --profile, or run in CloudShell)",
            file=sys.stderr,
        )
        return 2
    except (ClientError, BotoCoreError) as err:
        print(f"aws-audit: {err}", file=sys.stderr)
        return 2

    result.findings = [f for f in result.findings if f.severity >= min_severity]

    if args.format == "json":
        text = report.to_json(result)
    elif args.format == "markdown":
        text = report.to_markdown(result)
    else:
        colour = not args.no_colour and not args.output and sys.stdout.isatty()
        text = report.to_text(result, colour=colour)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
