from conftest import REGION

from aws_auditor.checks import rds, trail


def _db(session, name, public, encrypted):
    session.client("rds", region_name=REGION).create_db_instance(
        DBInstanceIdentifier=name,
        DBInstanceClass="db.t4g.micro",
        Engine="postgres",
        MasterUsername="admin1",
        MasterUserPassword="Sup3r-secret-pass",
        AllocatedStorage=20,
        PubliclyAccessible=public,
        StorageEncrypted=encrypted,
    )


def test_public_and_unencrypted_databases(session):
    _db(session, "open-db", public=True, encrypted=False)
    _db(session, "good-db", public=False, encrypted=True)

    public = rds.publicly_accessible(session, REGION)
    plain = rds.unencrypted(session, REGION)

    assert [f.resource.split(":")[-1] for f in public] == ["open-db"]
    assert [f.resource.split(":")[-1] for f in plain] == ["open-db"]


def test_no_trail_is_flagged_and_a_logging_trail_is_not(session):
    assert len(trail.cloudtrail(session, REGION)) == 1

    session.client("s3").create_bucket(
        Bucket="trail-logs", CreateBucketConfiguration={"LocationConstraint": REGION}
    )
    client = session.client("cloudtrail", region_name=REGION)
    client.create_trail(Name="main", S3BucketName="trail-logs", IsMultiRegionTrail=True)
    client.start_logging(Name="main")

    assert trail.cloudtrail(session, REGION) == []
