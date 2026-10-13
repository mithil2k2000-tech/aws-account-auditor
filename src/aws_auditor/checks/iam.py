"""Identity checks. IAM is global, so these run once."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import boto3
from botocore.exceptions import ClientError

from ..models import Finding, Severity

MAX_KEY_AGE = timedelta(days=90)


def root_access_keys(session: boto3.Session, region: str) -> list[Finding]:
    summary = session.client("iam").get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent", 0):
        return [
            Finding(
                check="iam-root-access-keys",
                severity=Severity.CRITICAL,
                resource="root user",
                region="global",
                message="The root user has access keys. Anyone holding them controls the whole "
                "account, and root can't be restricted by policy.",
                remediation="Delete the root access keys (Security credentials page, signed in as "
                "root) and use an IAM role or user for programmatic access.",
            )
        ]
    return []


def root_mfa(session: boto3.Session, region: str) -> list[Finding]:
    summary = session.client("iam").get_account_summary()["SummaryMap"]
    if not summary.get("AccountMFAEnabled", 0):
        return [
            Finding(
                check="iam-root-mfa",
                severity=Severity.CRITICAL,
                resource="root user",
                region="global",
                message="The root user has no MFA device: a leaked password is enough to take over "
                "the account.",
                remediation="Sign in as root and add an MFA device (a passkey or authenticator app).",
            )
        ]
    return []


def _has_console_password(client, user: str) -> bool:
    try:
        client.get_login_profile(UserName=user)
        return True
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def users_without_mfa(session: boto3.Session, region: str) -> list[Finding]:
    client = session.client("iam")
    findings = []
    for page in client.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if not _has_console_password(client, name):
                continue  # no console sign-in, so MFA wouldn't protect anything
            if client.list_mfa_devices(UserName=name)["MFADevices"]:
                continue
            findings.append(
                Finding(
                    check="iam-user-mfa",
                    severity=Severity.HIGH,
                    resource=user["Arn"],
                    region="global",
                    message=f"User {name} can sign in to the console with only a password.",
                    remediation="Add an MFA device for the user, or remove the console password if "
                    "they don't need console access.",
                )
            )
    return findings


def old_access_keys(
    session: boto3.Session, region: str, now: datetime | None = None
) -> list[Finding]:
    client = session.client("iam")
    now = now or datetime.now(UTC)
    findings = []
    for page in client.get_paginator("list_users").paginate():
        for user in page["Users"]:
            keys = client.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            for key in keys:
                age = now - key["CreateDate"]
                if key["Status"] == "Active" and age > MAX_KEY_AGE:
                    findings.append(
                        Finding(
                            check="iam-old-access-keys",
                            severity=Severity.MEDIUM,
                            resource=f"{user['Arn']} key {key['AccessKeyId']}",
                            region="global",
                            message=f"Access key {key['AccessKeyId']} for {user['UserName']} is "
                            f"{age.days} days old.",
                            remediation="Create a new key, move whatever uses this one over, then "
                            "deactivate and delete the old key. Better: use a role.",
                            details={"age_days": age.days},
                        )
                    )
    return findings
