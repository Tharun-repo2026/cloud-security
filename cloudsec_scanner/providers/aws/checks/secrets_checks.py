"""AWS secrets & data-exposure checks."""
from __future__ import annotations

import re

from cloudsec_scanner.core.finding import Category, Finding, Severity
from cloudsec_scanner.core.scanner_base import BaseCheck, register_aws_check

# Heuristic patterns for plaintext secrets leaking into config/env vars.
# Intentionally conservative to keep false positives low.
SECRET_KEY_PATTERN = re.compile(
    r"(?:secret|password|passwd|api[_-]?key|access[_-]?key|token)",
    re.IGNORECASE,
)
AWS_KEY_ID_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")


def _all_regions(session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]


@register_aws_check
class LambdaPlaintextSecretsCheck(BaseCheck):
    check_id = "AWS_SEC_001"
    title = "Lambda function has likely secrets in plaintext environment variables"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            lam = self.session.client("lambda", region_name=region)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    env = fn.get("Environment", {}).get("Variables", {}) or {}
                    kms = fn.get("KMSKeyArn")
                    suspicious_keys = [k for k in env if SECRET_KEY_PATTERN.search(k)]
                    hardcoded_key_id = any(
                        AWS_KEY_ID_PATTERN.search(str(v)) for v in env.values()
                    )
                    if hardcoded_key_id:
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.CRITICAL,
                            category=Category.SECRETS,
                            provider="aws",
                            resource_id=fn["FunctionArn"],
                            resource_type="lambda_function",
                            region=region,
                            description=f"Function '{fn['FunctionName']}' has "
                                        f"an environment variable containing "
                                        f"what looks like a raw AWS access "
                                        f"key ID.",
                            remediation="Remove hardcoded credentials; use "
                                        "an IAM execution role instead of "
                                        "static keys.",
                        ))
                    elif suspicious_keys and not kms:
                        findings.append(Finding(
                            check_id=self.check_id,
                            title="Lambda secrets-like env vars without KMS encryption",
                            severity=Severity.HIGH,
                            category=Category.SECRETS,
                            provider="aws",
                            resource_id=fn["FunctionArn"],
                            resource_type="lambda_function",
                            region=region,
                            description=f"Function '{fn['FunctionName']}' has "
                                        f"env vars named like secrets "
                                        f"({', '.join(suspicious_keys[:5])}) "
                                        f"but no customer-managed KMS key "
                                        f"is configured to encrypt them.",
                            remediation="Move secrets to AWS Secrets "
                                        "Manager or SSM Parameter Store "
                                        "(SecureString) and reference them "
                                        "at runtime instead of storing "
                                        "them as plaintext env vars.",
                            evidence={"suspicious_keys": suspicious_keys},
                        ))
        return findings


@register_aws_check
class SecretsManagerRotationCheck(BaseCheck):
    check_id = "AWS_SEC_002"
    title = "Secrets Manager secret has rotation disabled"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            sm = self.session.client("secretsmanager", region_name=region)
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page["SecretList"]:
                    if not secret.get("RotationEnabled"):
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.LOW,
                            category=Category.SECRETS,
                            provider="aws",
                            resource_id=secret["ARN"],
                            resource_type="secretsmanager_secret",
                            region=region,
                            description=f"Secret '{secret['Name']}' does not "
                                        f"have automatic rotation enabled.",
                            remediation="Enable automatic rotation "
                                        "(especially for DB credentials) "
                                        "using a rotation Lambda.",
                        ))
        return findings


@register_aws_check
class PublicRDSSnapshotCheck(BaseCheck):
    check_id = "AWS_SEC_003"
    title = "RDS snapshot is shared publicly"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        for region in _all_regions(self.session):
            rds = self.session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_snapshots")
            for page in paginator.paginate(SnapshotType="manual"):
                for snap in page["DBSnapshots"]:
                    attrs = rds.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snap["DBSnapshotIdentifier"]
                    )["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
                    for attr in attrs:
                        if attr["AttributeName"] == "restore" and "all" in attr["AttributeValues"]:
                            findings.append(Finding(
                                check_id=self.check_id,
                                title=self.title,
                                severity=Severity.CRITICAL,
                                category=Category.SECRETS,
                                provider="aws",
                                resource_id=snap["DBSnapshotArn"],
                                resource_type="rds_snapshot",
                                region=region,
                                description=f"RDS snapshot "
                                            f"'{snap['DBSnapshotIdentifier']}' "
                                            f"is shared with ALL AWS "
                                            f"accounts (public).",
                                remediation="Remove the 'all' restore "
                                            "attribute immediately and "
                                            "share only with specific "
                                            "account IDs if sharing is "
                                            "required.",
                            ))
        return findings
