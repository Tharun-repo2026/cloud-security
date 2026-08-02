"""AWS data-store checks: RDS and EBS exposure/encryption."""
from __future__ import annotations

from cloudsec_scanner.core.finding import Category, Finding, Severity
from cloudsec_scanner.core.scanner_base import BaseCheck, register_aws_check


def _all_regions(session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]


@register_aws_check
class RDSPubliclyAccessibleCheck(BaseCheck):
    check_id = "AWS_DATA_001"
    title = "RDS instance is publicly accessible"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            rds = self.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    if db.get("PubliclyAccessible"):
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.CRITICAL,
                            category=Category.NETWORK,
                            provider="aws",
                            resource_id=db["DBInstanceArn"],
                            resource_type="rds_instance",
                            region=region,
                            description=f"RDS instance "
                                        f"'{db['DBInstanceIdentifier']}' has "
                                        f"PubliclyAccessible=true, exposing "
                                        f"the database to the internet.",
                            remediation="Set PubliclyAccessible to false "
                                        "and access the database via "
                                        "VPC-internal routes, a bastion, "
                                        "or VPN/Direct Connect.",
                        ))
        return findings


@register_aws_check
class RDSEncryptionCheck(BaseCheck):
    check_id = "AWS_DATA_002"
    title = "RDS instance storage is not encrypted"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            rds = self.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    if not db.get("StorageEncrypted"):
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.HIGH,
                            category=Category.ENCRYPTION,
                            provider="aws",
                            resource_id=db["DBInstanceArn"],
                            resource_type="rds_instance",
                            region=region,
                            description=f"RDS instance "
                                        f"'{db['DBInstanceIdentifier']}' "
                                        f"does not have storage encryption "
                                        f"enabled.",
                            remediation="Storage encryption can't be "
                                        "toggled in place — create an "
                                        "encrypted snapshot and restore to "
                                        "a new encrypted instance, then "
                                        "cut over.",
                        ))
        return findings


@register_aws_check
class EBSUnencryptedVolumeCheck(BaseCheck):
    check_id = "AWS_DATA_003"
    title = "EBS volume is not encrypted"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            ec2 = self.session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page["Volumes"]:
                    if not vol.get("Encrypted"):
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            category=Category.ENCRYPTION,
                            provider="aws",
                            resource_id=vol["VolumeId"],
                            resource_type="ebs_volume",
                            region=region,
                            description=f"EBS volume {vol['VolumeId']} is "
                                        f"unencrypted.",
                            remediation="Enable EBS encryption by default "
                                        "for the account/region, and "
                                        "migrate existing volumes via "
                                        "snapshot-copy-encrypt-restore.",
                        ))
        return findings


@register_aws_check
class EBSPublicSnapshotCheck(BaseCheck):
    check_id = "AWS_DATA_004"
    title = "EBS snapshot is shared publicly"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            ec2 = self.session.client("ec2", region_name=region)
            snaps = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
            for snap in snaps:
                attrs = ec2.describe_snapshot_attribute(
                    SnapshotId=snap["SnapshotId"], Attribute="createVolumePermission"
                )["CreateVolumePermissions"]
                if any(p.get("Group") == "all" for p in attrs):
                    findings.append(Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=Severity.CRITICAL,
                        category=Category.SECRETS,
                        provider="aws",
                        resource_id=snap["SnapshotId"],
                        resource_type="ebs_snapshot",
                        region=region,
                        description=f"EBS snapshot {snap['SnapshotId']} is "
                                    f"shared publicly (createVolumePermission "
                                    f"= all).",
                        remediation="Remove the public create-volume "
                                    "permission; share only with specific "
                                    "account IDs if needed.",
                    ))
        return findings
