"""Runs the checks across regions and collects what they find.

A check that fails (a service not enabled, a permission missing) is
recorded as an error and the audit carries on: one unreadable service
shouldn't hide what every other check found.
"""

from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .checks import Check
from .models import Finding


@dataclass
class AuditResult:
    account_id: str
    regions: list[str]
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.check, f.region, f.resource))


def enabled_regions(session: boto3.Session) -> list[str]:
    client = session.client("ec2", region_name=session.region_name or "us-east-1")
    regions = client.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )["Regions"]
    return sorted(r["RegionName"] for r in regions)


def _run_one(check: Check, session: boto3.Session, region: str):
    try:
        return check, region, check.fn(session, region), None
    except (ClientError, BotoCoreError) as err:
        return check, region, [], str(err)


def run_audit(
    session: boto3.Session, checks: Iterable[Check], regions: list[str], workers: int = 8
) -> AuditResult:
    account_id = session.client("sts").get_caller_identity()["Account"]
    result = AuditResult(account_id=account_id, regions=regions)

    jobs = []
    for check in checks:
        targets = [regions[0]] if check.global_service else regions
        jobs.extend((check, region) for region in targets)

    # boto3 sessions aren't thread-safe for creating clients, but each
    # check creates its own clients from the session, so give each worker
    # thread its own copy of the session's credentials.
    def worker(job):
        check, region = job
        local = boto3.Session(
            aws_access_key_id=creds.access_key,
            aws_secret_access_key=creds.secret_key,
            aws_session_token=creds.token,
            region_name=region,
        )
        return _run_one(check, local, region)

    creds = session.get_credentials().get_frozen_credentials()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for check, region, findings, error in pool.map(worker, jobs):
            result.findings.extend(findings)
            if error:
                result.errors.append({"check": check.name, "region": region, "error": error})
    return result
