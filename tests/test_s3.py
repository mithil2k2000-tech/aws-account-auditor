from conftest import REGION

from aws_auditor.checks import s3

LOCATION = {"LocationConstraint": REGION}
ALL_BLOCKED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def test_bucket_without_public_access_block_is_flagged(session):
    session.client("s3").create_bucket(Bucket="open-bucket", CreateBucketConfiguration=LOCATION)

    findings = s3.public_access(session, REGION)

    assert [f.resource for f in findings] == ["arn:aws:s3:::open-bucket"]
    assert findings[0].region == REGION
    assert len(findings[0].details["missing"]) == 4


def test_fully_blocked_bucket_is_not_flagged(session):
    client = session.client("s3")
    client.create_bucket(Bucket="closed-bucket", CreateBucketConfiguration=LOCATION)
    client.put_public_access_block(
        Bucket="closed-bucket", PublicAccessBlockConfiguration=ALL_BLOCKED
    )

    assert s3.public_access(session, REGION) == []


def test_partly_blocked_bucket_names_what_is_missing(session):
    client = session.client("s3")
    client.create_bucket(Bucket="half-bucket", CreateBucketConfiguration=LOCATION)
    client.put_public_access_block(
        Bucket="half-bucket",
        PublicAccessBlockConfiguration={**ALL_BLOCKED, "BlockPublicPolicy": False},
    )

    findings = s3.public_access(session, REGION)

    assert findings[0].details["missing"] == ["BlockPublicPolicy"]


def test_versioning(session):
    client = session.client("s3")
    client.create_bucket(Bucket="plain", CreateBucketConfiguration=LOCATION)
    client.create_bucket(Bucket="versioned", CreateBucketConfiguration=LOCATION)
    client.put_bucket_versioning(Bucket="versioned", VersioningConfiguration={"Status": "Enabled"})

    findings = s3.versioning(session, REGION)

    assert [f.resource for f in findings] == ["arn:aws:s3:::plain"]
