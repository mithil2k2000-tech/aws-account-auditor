from datetime import UTC, datetime, timedelta

from conftest import REGION

from aws_auditor.checks import cost


def test_unattached_volume_is_priced(session):
    client = session.client("ec2", region_name=REGION)
    client.create_volume(AvailabilityZone=f"{REGION}a", Size=100, VolumeType="gp3")

    findings = cost.unattached_volumes(session, REGION)

    assert len(findings) == 1
    assert findings[0].monthly_cost_usd == 8.0  # 100 GB x $0.08


def test_unassociated_elastic_ip_is_flagged(session):
    session.client("ec2", region_name=REGION).allocate_address(Domain="vpc")

    findings = cost.idle_elastic_ips(session, REGION)

    assert len(findings) == 1
    assert findings[0].monthly_cost_usd == 3.65  # $0.005 x 730 hours


def test_snapshots_only_flagged_once_old(session):
    client = session.client("ec2", region_name=REGION)
    volume = client.create_volume(AvailabilityZone=f"{REGION}a", Size=10)["VolumeId"]
    snapshot = client.create_snapshot(VolumeId=volume)["SnapshotId"]

    def ours(findings):
        # moto also lists snapshots behind its built-in images; ignore those.
        return [f for f in findings if f.resource == snapshot]

    assert ours(cost.old_snapshots(session, REGION)) == []
    later = datetime.now(UTC) + timedelta(days=200)
    assert len(ours(cost.old_snapshots(session, REGION, now=later))) == 1
