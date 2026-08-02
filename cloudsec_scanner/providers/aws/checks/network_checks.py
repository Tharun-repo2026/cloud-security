"""AWS network checks: security groups, VPC hygiene."""
from __future__ import annotations

from cloudsec_scanner.core.finding import Category, Finding, Severity
from cloudsec_scanner.core.scanner_base import BaseCheck, register_aws_check

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}


def _all_regions(session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]


def _is_open_to_world(ip_ranges) -> bool:
    return any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges)


@register_aws_check
class OpenSecurityGroupSensitivePortCheck(BaseCheck):
    check_id = "AWS_NET_001"
    title = "Security group allows 0.0.0.0/0 ingress on a sensitive port"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            ec2 = self.session.client("ec2", region_name=region)
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    if not _is_open_to_world(perm.get("IpRanges", [])):
                        continue
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    for port, name in SENSITIVE_PORTS.items():
                        in_range = (
                            from_port is not None and to_port is not None
                            and from_port <= port <= to_port
                        )
                        if in_range:
                            findings.append(Finding(
                                check_id=self.check_id,
                                title=self.title,
                                severity=Severity.CRITICAL,
                                category=Category.NETWORK,
                                provider="aws",
                                resource_id=sg["GroupId"],
                                resource_type="security_group",
                                region=region,
                                description=f"Security group '{sg['GroupName']}' "
                                            f"({sg['GroupId']}) allows inbound "
                                            f"{name} (port {port}) from "
                                            f"0.0.0.0/0.",
                                remediation=f"Restrict port {port} to specific "
                                            f"known IP ranges or a bastion/"
                                            f"VPN, never 0.0.0.0/0.",
                                evidence={"port": port, "service": name},
                            ))
        return findings


@register_aws_check
class OpenSecurityGroupAllPortsCheck(BaseCheck):
    check_id = "AWS_NET_002"
    title = "Security group allows all ports/protocols from 0.0.0.0/0"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            ec2 = self.session.client("ec2", region_name=region)
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    if not _is_open_to_world(perm.get("IpRanges", [])):
                        continue
                    if perm.get("IpProtocol") == "-1":
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.CRITICAL,
                            category=Category.NETWORK,
                            provider="aws",
                            resource_id=sg["GroupId"],
                            resource_type="security_group",
                            region=region,
                            description=f"Security group '{sg['GroupName']}' "
                                        f"({sg['GroupId']}) allows ALL "
                                        f"protocols/ports from 0.0.0.0/0.",
                            remediation="Remove the all-traffic rule and "
                                        "define explicit ports/protocols "
                                        "the workload actually needs.",
                        ))
        return findings


@register_aws_check
class DefaultVPCInUseCheck(BaseCheck):
    check_id = "AWS_NET_003"
    title = "Default VPC still present"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            ec2 = self.session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs(
                Filters=[{"Name": "isDefault", "Values": ["true"]}]
            )["Vpcs"]
            for vpc in vpcs:
                findings.append(Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.LOW,
                    category=Category.NETWORK,
                    provider="aws",
                    resource_id=vpc["VpcId"],
                    resource_type="vpc",
                    region=region,
                    description=f"Default VPC {vpc['VpcId']} exists in "
                                f"{region}. Default VPCs have permissive "
                                f"default routing/ACLs and are a common "
                                f"source of accidental exposure.",
                    remediation="Delete unused default VPCs, or lock down "
                                "their default security group and route "
                                "tables if they must stay.",
                ))
        return findings


@register_aws_check
class VPCFlowLogsDisabledCheck(BaseCheck):
    check_id = "AWS_NET_004"
    title = "VPC has no Flow Logs enabled"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            ec2 = self.session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs()["Vpcs"]
            flow_logs = ec2.describe_flow_logs()["FlowLogs"]
            vpcs_with_logs = {fl["ResourceId"] for fl in flow_logs}
            for vpc in vpcs:
                if vpc["VpcId"] not in vpcs_with_logs:
                    findings.append(Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        category=Category.LOGGING,
                        provider="aws",
                        resource_id=vpc["VpcId"],
                        resource_type="vpc",
                        region=region,
                        description=f"VPC {vpc['VpcId']} in {region} has no "
                                    f"Flow Logs, limiting network forensics "
                                    f"and anomaly detection.",
                        remediation="Enable VPC Flow Logs to CloudWatch "
                                    "Logs or S3 for all production VPCs.",
                    ))
        return findings
