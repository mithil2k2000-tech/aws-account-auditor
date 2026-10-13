import pytest
from conftest import REGION, checks_named

from aws_auditor.checks import ec2


def _group(client, name, permissions):
    vpc = client.describe_vpcs()["Vpcs"][0]["VpcId"]
    group = client.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
    client.authorize_security_group_ingress(GroupId=group, IpPermissions=permissions)
    return group


def _rule(port_from, port_to, cidr="0.0.0.0/0", protocol="tcp"):
    return {
        "IpProtocol": protocol,
        "FromPort": port_from,
        "ToPort": port_to,
        "IpRanges": [{"CidrIp": cidr}],
    }


def test_ssh_open_to_the_world_is_flagged(session):
    client = session.client("ec2", region_name=REGION)
    group = _group(client, "ssh-open", [_rule(22, 22)])

    findings = [f for f in ec2.open_admin_ports(session, REGION) if group in f.resource]

    assert [f.details["port"] for f in findings] == [22]
    assert "SSH" in findings[0].message


def test_https_open_to_the_world_is_fine(session):
    client = session.client("ec2", region_name=REGION)
    group = _group(client, "web", [_rule(443, 443)])

    assert not [f for f in ec2.open_admin_ports(session, REGION) if group in f.resource]


def test_admin_port_open_to_a_private_range_is_fine(session):
    client = session.client("ec2", region_name=REGION)
    group = _group(client, "internal", [_rule(5432, 5432, cidr="10.0.0.0/16")])

    assert not [f for f in ec2.open_admin_ports(session, REGION) if group in f.resource]


def test_port_range_covering_admin_ports_flags_each(session):
    client = session.client("ec2", region_name=REGION)
    group = _group(client, "wide", [_rule(20, 3400)])

    ports = sorted(
        f.details["port"] for f in ec2.open_admin_ports(session, REGION) if group in f.resource
    )
    assert ports == [22, 1433, 3306, 3389]


@pytest.fixture
def instance(session):
    client = session.client("ec2", region_name=REGION)
    image = client.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    return client.run_instances(ImageId=image, MinCount=1, MaxCount=1, InstanceType="t3.micro")[
        "Instances"
    ][0]["InstanceId"]


def test_untagged_instance_is_flagged(session, instance):
    findings = ec2.missing_tags(session, REGION)
    assert [f.resource for f in findings] == [instance]
    assert findings[0].details["missing"] == ["Project", "Owner"]


def test_tagged_instance_is_not_flagged(session, instance):
    session.client("ec2", region_name=REGION).create_tags(
        Resources=[instance],
        Tags=[{"Key": "Project", "Value": "x"}, {"Key": "Owner", "Value": "me"}],
    )
    assert ec2.missing_tags(session, REGION) == []


def test_imdsv1_flagged_until_tokens_required(session, instance):
    assert checks_named(ec2.imdsv1_allowed(session, REGION), "ec2-imdsv1")

    session.client("ec2", region_name=REGION).modify_instance_metadata_options(
        InstanceId=instance, HttpTokens="required"
    )
    assert ec2.imdsv1_allowed(session, REGION) == []
