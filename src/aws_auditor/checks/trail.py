"""Audit-trail checks, per region."""

from __future__ import annotations

import boto3

from ..models import Finding, Severity


def cloudtrail(session: boto3.Session, region: str) -> list[Finding]:
    client = session.client("cloudtrail", region_name=region)
    # Includes multi-region trails created in other regions.
    for trail in client.describe_trails(includeShadowTrails=True)["trailList"]:
        status = client.get_trail_status(Name=trail["TrailARN"])
        if status.get("IsLogging"):
            return []
    return [
        Finding(
            check="cloudtrail-enabled",
            severity=Severity.MEDIUM,
            resource="CloudTrail",
            region=region,
            message="No trail is logging this region. Event history keeps 90 days of management "
            "events, but nothing is kept beyond that or written somewhere you control.",
            remediation="Create one multi-region trail writing to an S3 bucket with versioning and "
            "Block Public Access on.",
        )
    ]
