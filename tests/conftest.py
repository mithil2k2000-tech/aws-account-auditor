"""Every test runs against moto's in-memory AWS. Nothing here can reach a
real account: the credentials are fake and every call is intercepted."""

import boto3
import pytest
from moto import mock_aws

REGION = "eu-west-2"


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": REGION,
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.Session(region_name=REGION)


def checks_named(findings, name):
    return [f for f in findings if f.check == name]
