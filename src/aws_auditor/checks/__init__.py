"""Every check, and the services each one needs.

A check is a function (session, region) -> list[Finding]. It only reads:
nothing here creates, changes or deletes anything. Global services (IAM,
S3's bucket list) are marked so they run once, not once per region.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import boto3

from ..models import Finding
from . import cost, ec2, iam, rds, s3, trail

CheckFn = Callable[[boto3.Session, str], list[Finding]]


@dataclass(frozen=True)
class Check:
    name: str
    description: str
    fn: CheckFn
    global_service: bool = False


CHECKS: list[Check] = [
    Check("iam-root-access-keys", "The root user has access keys", iam.root_access_keys, True),
    Check("iam-root-mfa", "The root user has no MFA device", iam.root_mfa, True),
    Check("iam-user-mfa", "Console users without MFA", iam.users_without_mfa, True),
    Check(
        "iam-old-access-keys", "Active access keys older than 90 days", iam.old_access_keys, True
    ),
    Check("s3-public-access", "Buckets not fully blocking public access", s3.public_access, True),
    Check("s3-versioning", "Buckets without versioning", s3.versioning, True),
    Check(
        "ec2-open-admin-ports", "SSH/RDP/database ports open to the internet", ec2.open_admin_ports
    ),
    Check("ec2-required-tags", "Instances missing required tags", ec2.missing_tags),
    Check("ec2-imdsv1", "Instances still allowing IMDSv1", ec2.imdsv1_allowed),
    Check("rds-public", "Databases reachable from the internet", rds.publicly_accessible),
    Check("rds-unencrypted", "Databases without storage encryption", rds.unencrypted),
    Check("cloudtrail-enabled", "No CloudTrail trail logging in the region", trail.cloudtrail),
    Check("cost-unattached-volumes", "EBS volumes attached to nothing", cost.unattached_volumes),
    Check("cost-idle-elastic-ips", "Elastic IPs attached to nothing", cost.idle_elastic_ips),
    Check("cost-old-snapshots", "EBS snapshots older than 180 days", cost.old_snapshots),
]


def by_name(names: list[str] | None) -> list[Check]:
    if not names:
        return list(CHECKS)
    known = {c.name: c for c in CHECKS}
    unknown = [n for n in names if n not in known]
    if unknown:
        raise ValueError(f"unknown check(s): {', '.join(unknown)}")
    return [known[n] for n in names]
