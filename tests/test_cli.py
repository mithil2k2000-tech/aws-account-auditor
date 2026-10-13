import json

import boto3
import pytest
from conftest import REGION
from moto import mock_aws

from aws_auditor import cli
from aws_auditor.checks import CHECKS
from aws_auditor.runner import run_audit


@pytest.fixture
def risky_account():
    """An account with one problem of each common kind."""
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(
            Bucket="open-bucket", CreateBucketConfiguration={"LocationConstraint": REGION}
        )
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
        group = ec2.create_security_group(GroupName="ssh", Description="ssh", VpcId=vpc)
        ec2.authorize_security_group_ingress(
            GroupId=group["GroupId"],
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=50)
        yield


def test_every_check_runs_without_errors(risky_account):
    result = run_audit(boto3.Session(region_name=REGION), CHECKS, [REGION])

    assert result.errors == []
    found = {f.check for f in result.findings}
    assert {"s3-public-access", "ec2-open-admin-ports", "cost-unattached-volumes"} <= found


def test_global_checks_run_once_across_regions(risky_account):
    result = run_audit(boto3.Session(region_name=REGION), CHECKS, [REGION, "us-east-1"])

    s3_findings = [f for f in result.findings if f.check == "s3-public-access"]
    assert len(s3_findings) == 1


def test_json_report_and_exit_code(risky_account, capsys):
    code = cli.main(["--regions", REGION, "--format", "json", "--fail-on", "high"])

    report = json.loads(capsys.readouterr().out)
    assert code == 1  # an open SSH port and a public-capable bucket are HIGH
    assert report["summary"]["HIGH"] >= 2
    assert report["estimated_monthly_waste_usd"] == 5.0  # the 50 GB volume (gp2, $0.10/GB)
    assert report["findings"][0]["severity"] in ("CRITICAL", "HIGH")


def test_fail_on_none_always_exits_zero(risky_account, capsys):
    assert cli.main(["--regions", REGION, "--fail-on", "none", "--no-colour"]) == 0
    assert "Findings:" in capsys.readouterr().out


def test_min_severity_filters_the_report(risky_account, capsys):
    cli.main(
        ["--regions", REGION, "--format", "json", "--min-severity", "high", "--fail-on", "none"]
    )
    report = json.loads(capsys.readouterr().out)
    assert {f["severity"] for f in report["findings"]} <= {"HIGH", "CRITICAL"}


def test_markdown_report_to_file(risky_account, tmp_path):
    out = tmp_path / "report.md"
    cli.main(["--regions", REGION, "--format", "markdown", "-o", str(out), "--fail-on", "none"])
    text = out.read_text()
    assert text.startswith("# AWS account audit")
    assert "## HIGH: ec2-open-admin-ports" in text


def test_bad_arguments_exit_two(capsys):
    assert cli.main(["--checks", "no-such-check"]) == 2
    assert cli.main(["--fail-on", "apocalyptic"]) == 2


def test_list_checks(capsys):
    assert cli.main(["--list-checks"]) == 0
    assert "s3-public-access" in capsys.readouterr().out
