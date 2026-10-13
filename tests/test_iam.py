from datetime import UTC, datetime, timedelta

from conftest import REGION

from aws_auditor.checks import iam
from aws_auditor.models import Severity


def test_console_user_without_mfa_is_flagged(session):
    client = session.client("iam")
    client.create_user(UserName="alice")
    client.create_login_profile(UserName="alice", Password="Sup3r-secret-pass!")

    findings = iam.users_without_mfa(session, REGION)

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "alice" in findings[0].message


def test_user_without_console_password_is_not_flagged(session):
    session.client("iam").create_user(UserName="ci-bot")
    assert iam.users_without_mfa(session, REGION) == []


def test_access_keys_older_than_90_days_are_flagged(session):
    client = session.client("iam")
    client.create_user(UserName="bob")
    client.create_access_key(UserName="bob")

    assert iam.old_access_keys(session, REGION) == []  # brand new

    later = datetime.now(UTC) + timedelta(days=120)
    findings = iam.old_access_keys(session, REGION, now=later)
    assert len(findings) == 1
    assert findings[0].details["age_days"] >= 119


def test_inactive_old_keys_are_ignored(session):
    client = session.client("iam")
    client.create_user(UserName="carol")
    key = client.create_access_key(UserName="carol")["AccessKey"]["AccessKeyId"]
    client.update_access_key(UserName="carol", AccessKeyId=key, Status="Inactive")

    later = datetime.now(UTC) + timedelta(days=365)
    assert iam.old_access_keys(session, REGION, now=later) == []


def test_root_without_mfa_is_critical(session):
    findings = iam.root_mfa(session, REGION)
    assert [f.severity for f in findings] == [Severity.CRITICAL]
