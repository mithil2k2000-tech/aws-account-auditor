"""Network and instance checks, per region."""

from __future__ import annotations

import boto3

from ..models import Finding, Severity

# Ports that should never be open to the whole internet.
ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    6379: "Redis",
    27017: "MongoDB",
}
WORLD = {"0.0.0.0/0", "::/0"}

# Overridden by --require-tag on the command line.
REQUIRED_TAGS: tuple[str, ...] = ("Project", "Owner")


def _world_sources(permission: dict) -> list[str]:
    v4 = [r["CidrIp"] for r in permission.get("IpRanges", []) if r.get("CidrIp") in WORLD]
    v6 = [r["CidrIpv6"] for r in permission.get("Ipv6Ranges", []) if r.get("CidrIpv6") in WORLD]
    return v4 + v6


def _exposed_ports(permission: dict) -> list[int]:
    if permission.get("IpProtocol") == "-1":  # all traffic
        return sorted(ADMIN_PORTS)
    if permission.get("IpProtocol") not in ("tcp", "6"):
        return []
    low, high = permission.get("FromPort", 0), permission.get("ToPort", 65535)
    return [port for port in sorted(ADMIN_PORTS) if low <= port <= high]


def open_admin_ports(session: boto3.Session, region: str) -> list[Finding]:
    client = session.client("ec2", region_name=region)
    findings = []
    for page in client.get_paginator("describe_security_groups").paginate():
        for group in page["SecurityGroups"]:
            for permission in group.get("IpPermissions", []):
                sources = _world_sources(permission)
                if not sources:
                    continue
                for port in _exposed_ports(permission):
                    findings.append(
                        Finding(
                            check="ec2-open-admin-ports",
                            severity=Severity.HIGH,
                            resource=f"{group['GroupId']} ({group.get('GroupName', '')})",
                            region=region,
                            message=f"{ADMIN_PORTS[port]} (port {port}) is open to "
                            f"{' and '.join(sources)}.",
                            remediation="Restrict the rule to known addresses, or remove it and use "
                            "SSM Session Manager instead of opening SSH/RDP at all.",
                            details={"port": port, "sources": sources, "vpc": group.get("VpcId")},
                        )
                    )
    return findings


def _instances(client):
    for page in client.get_paginator("describe_instances").paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                if instance["State"]["Name"] != "terminated":
                    yield instance


def missing_tags(session: boto3.Session, region: str) -> list[Finding]:
    client = session.client("ec2", region_name=region)
    findings = []
    for instance in _instances(client):
        tags = {t["Key"] for t in instance.get("Tags", [])}
        missing = [t for t in REQUIRED_TAGS if t not in tags]
        if missing:
            findings.append(
                Finding(
                    check="ec2-required-tags",
                    severity=Severity.LOW,
                    resource=instance["InstanceId"],
                    region=region,
                    message=f"Instance {instance['InstanceId']} has no {', '.join(missing)} tag, so "
                    "nobody can tell from the bill who owns it or what it's for.",
                    remediation="Add the tags, and enforce them with a tag policy or an SCP.",
                    details={"missing": missing},
                )
            )
    return findings


def imdsv1_allowed(session: boto3.Session, region: str) -> list[Finding]:
    client = session.client("ec2", region_name=region)
    findings = []
    for instance in _instances(client):
        if instance.get("MetadataOptions", {}).get("HttpTokens") != "required":
            findings.append(
                Finding(
                    check="ec2-imdsv1",
                    severity=Severity.MEDIUM,
                    resource=instance["InstanceId"],
                    region=region,
                    message=f"Instance {instance['InstanceId']} still accepts IMDSv1, which lets a "
                    "server-side request forgery bug read the instance's credentials.",
                    remediation="Require IMDSv2: aws ec2 modify-instance-metadata-options "
                    f"--instance-id {instance['InstanceId']} --http-tokens required",
                )
            )
    return findings
