"""Database checks, per region."""

from __future__ import annotations

import boto3

from ..models import Finding, Severity


def _databases(session: boto3.Session, region: str):
    client = session.client("rds", region_name=region)
    for page in client.get_paginator("describe_db_instances").paginate():
        yield from page["DBInstances"]


def publicly_accessible(session: boto3.Session, region: str) -> list[Finding]:
    return [
        Finding(
            check="rds-public",
            severity=Severity.HIGH,
            resource=db["DBInstanceArn"],
            region=region,
            message=f"Database {db['DBInstanceIdentifier']} has a public address; only its "
            "security group stands between it and the internet.",
            remediation="Set PubliclyAccessible to false and reach it from inside the VPC.",
        )
        for db in _databases(session, region)
        if db.get("PubliclyAccessible")
    ]


def unencrypted(session: boto3.Session, region: str) -> list[Finding]:
    return [
        Finding(
            check="rds-unencrypted",
            severity=Severity.MEDIUM,
            resource=db["DBInstanceArn"],
            region=region,
            message=f"Database {db['DBInstanceIdentifier']} stores data unencrypted, and so do "
            "its snapshots.",
            remediation="Encryption can't be switched on in place: snapshot, copy the snapshot "
            "with encryption, restore from the copy.",
        )
        for db in _databases(session, region)
        if not db.get("StorageEncrypted")
    ]
