"""Bucket checks. The bucket list is global, so these run once."""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ..models import Finding, Severity

_BLOCK_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _bucket_region(client, bucket: str) -> str:
    location = client.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    return location or "us-east-1"  # S3 reports us-east-1 as null


def _account_block(session: boto3.Session) -> dict:
    """The account-wide setting, which covers every bucket when fully on."""
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        config = session.client("s3control").get_public_access_block(AccountId=account_id)
        return config["PublicAccessBlockConfiguration"]
    except ClientError:
        return {}


def public_access(session: boto3.Session, region: str) -> list[Finding]:
    account = _account_block(session)
    if account and all(account.get(flag) for flag in _BLOCK_FLAGS):
        return []  # every bucket is covered by the account-wide block

    client = session.client("s3")
    findings = []
    for bucket in client.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            config = client.get_public_access_block(Bucket=name)
            flags = config["PublicAccessBlockConfiguration"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            flags = {}
        missing = [f for f in _BLOCK_FLAGS if not (flags.get(f) or account.get(f))]
        if missing:
            findings.append(
                Finding(
                    check="s3-public-access",
                    severity=Severity.HIGH,
                    resource=f"arn:aws:s3:::{name}",
                    region=_bucket_region(client, name),
                    message=f"Bucket {name} doesn't block public access ({', '.join(missing)} off), "
                    "so one wrong policy or ACL could expose it.",
                    remediation="Turn on all four Block Public Access settings for the bucket, or "
                    "for the whole account if no bucket should ever be public.",
                    details={"missing": missing},
                )
            )
    return findings


def versioning(session: boto3.Session, region: str) -> list[Finding]:
    client = session.client("s3")
    findings = []
    for bucket in client.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        status = client.get_bucket_versioning(Bucket=name).get("Status")
        if status != "Enabled":
            findings.append(
                Finding(
                    check="s3-versioning",
                    severity=Severity.LOW,
                    resource=f"arn:aws:s3:::{name}",
                    region=_bucket_region(client, name),
                    message=f"Bucket {name} has no versioning: an overwrite or delete can't be undone.",
                    remediation="Enable versioning, with a lifecycle rule to expire old versions so "
                    "storage doesn't grow for ever.",
                )
            )
    return findings
