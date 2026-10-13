"""Things being paid for that nothing uses, per region.

Prices are approximate list prices (USD, us-east-1, 2026) used only to
put a rough monthly figure on each finding. They are not your bill.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import boto3

from ..models import Finding, Severity

VOLUME_PRICE_PER_GB = {
    "gp3": 0.08,
    "gp2": 0.10,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}
IPV4_PRICE_PER_HOUR = 0.005
SNAPSHOT_PRICE_PER_GB = 0.05
HOURS_PER_MONTH = 730
SNAPSHOT_MAX_AGE = timedelta(days=180)


def unattached_volumes(session: boto3.Session, region: str) -> list[Finding]:
    client = session.client("ec2", region_name=region)
    findings = []
    pages = client.get_paginator("describe_volumes").paginate(
        Filters=[{"Name": "status", "Values": ["available"]}]
    )
    for page in pages:
        for volume in page["Volumes"]:
            price = VOLUME_PRICE_PER_GB.get(volume.get("VolumeType", "gp3"), 0.08)
            cost = round(volume["Size"] * price, 2)
            findings.append(
                Finding(
                    check="cost-unattached-volumes",
                    severity=Severity.LOW,
                    resource=volume["VolumeId"],
                    region=region,
                    message=f"{volume['Size']} GB {volume.get('VolumeType', '')} volume "
                    f"{volume['VolumeId']} is attached to nothing.",
                    remediation="Snapshot it if the data matters, then delete the volume.",
                    monthly_cost_usd=cost,
                )
            )
    return findings


def idle_elastic_ips(session: boto3.Session, region: str) -> list[Finding]:
    client = session.client("ec2", region_name=region)
    findings = []
    for address in client.describe_addresses()["Addresses"]:
        if address.get("AssociationId"):
            continue
        findings.append(
            Finding(
                check="cost-idle-elastic-ips",
                severity=Severity.LOW,
                resource=address.get("AllocationId", address.get("PublicIp", "?")),
                region=region,
                message=f"Elastic IP {address.get('PublicIp')} is allocated but attached to nothing.",
                remediation="Release it if nothing needs that exact address.",
                monthly_cost_usd=round(IPV4_PRICE_PER_HOUR * HOURS_PER_MONTH, 2),
            )
        )
    return findings


def old_snapshots(
    session: boto3.Session, region: str, now: datetime | None = None
) -> list[Finding]:
    client = session.client("ec2", region_name=region)
    now = now or datetime.now(UTC)
    findings = []
    for page in client.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
        for snap in page["Snapshots"]:
            age = now - snap["StartTime"]
            if age <= SNAPSHOT_MAX_AGE:
                continue
            findings.append(
                Finding(
                    check="cost-old-snapshots",
                    severity=Severity.INFO,
                    resource=snap["SnapshotId"],
                    region=region,
                    message=f"Snapshot {snap['SnapshotId']} ({snap.get('VolumeSize', 0)} GB) is "
                    f"{age.days} days old.",
                    remediation="Delete it if no restore would ever use it; for snapshots you do "
                    "need, Data Lifecycle Manager can expire them automatically.",
                    # Snapshots are incremental, so the full size is an upper bound.
                    monthly_cost_usd=round(snap.get("VolumeSize", 0) * SNAPSHOT_PRICE_PER_GB, 2),
                    details={"age_days": age.days},
                )
            )
    return findings
