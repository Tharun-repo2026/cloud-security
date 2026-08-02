"""AWS S3 checks: public exposure and baseline hygiene."""
from __future__ import annotations

from botocore.exceptions import ClientError

from cloudsec_scanner.core.finding import Category, Finding, Severity
from cloudsec_scanner.core.scanner_base import BaseCheck, register_aws_check


def _list_buckets(session):
    s3 = session.client("s3")
    return s3.list_buckets().get("Buckets", []), s3


@register_aws_check
class S3PublicAccessBlockCheck(BaseCheck):
    check_id = "AWS_S3_001"
    title = "S3 bucket without account/bucket-level Public Access Block"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        buckets, s3 = _list_buckets(self.session)
        for b in buckets:
            name = b["Name"]
            try:
                cfg = s3.get_public_access_block(Bucket=name)
                pab = cfg["PublicAccessBlockConfiguration"]
                fully_blocked = all(pab.get(k) for k in (
                    "BlockPublicAcls", "IgnorePublicAcls",
                    "BlockPublicPolicy", "RestrictPublicBuckets",
                ))
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    fully_blocked = False
                else:
                    raise
            if not fully_blocked:
                findings.append(Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    category=Category.MISCONFIGURATION,
                    provider="aws",
                    resource_id=name,
                    resource_type="s3_bucket",
                    region="global",
                    description=f"Bucket '{name}' does not have all four Public "
                                f"Access Block settings enabled, leaving it "
                                f"exposed to accidental public ACLs or policies.",
                    remediation="Enable BlockPublicAcls, IgnorePublicAcls, "
                                "BlockPublicPolicy, and RestrictPublicBuckets "
                                "at the bucket (or account) level unless the "
                                "bucket is intentionally a public website.",
                ))
        return findings


@register_aws_check
class S3PublicPolicyOrAclCheck(BaseCheck):
    check_id = "AWS_S3_002"
    title = "S3 bucket is publicly accessible via ACL or bucket policy"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        buckets, s3 = _list_buckets(self.session)
        for b in buckets:
            name = b["Name"]
            try:
                status = s3.get_bucket_policy_status(Bucket=name)
                is_public = status.get("PolicyStatus", {}).get("IsPublic", False)
            except ClientError:
                is_public = False
            if is_public:
                findings.append(Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    category=Category.MISCONFIGURATION,
                    provider="aws",
                    resource_id=name,
                    resource_type="s3_bucket",
                    region="global",
                    description=f"Bucket '{name}' policy grants public access "
                                f"per S3's own policy-status evaluation.",
                    remediation="Review and tighten the bucket policy to "
                                "remove wildcard Principals, or apply a "
                                "Public Access Block if public access is "
                                "unintended.",
                ))
        return findings


@register_aws_check
class S3EncryptionCheck(BaseCheck):
    check_id = "AWS_S3_003"
    title = "S3 bucket without default server-side encryption"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        buckets, s3 = _list_buckets(self.session)
        for b in buckets:
            name = b["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
                encrypted = True
            except ClientError as e:
                encrypted = e.response["Error"]["Code"] != \
                    "ServerSideEncryptionConfigurationNotFoundError"
            if not encrypted:
                findings.append(Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    category=Category.ENCRYPTION,
                    provider="aws",
                    resource_id=name,
                    resource_type="s3_bucket",
                    region="global",
                    description=f"Bucket '{name}' has no default encryption "
                                f"configuration (SSE-S3/SSE-KMS).",
                    remediation="Enable default bucket encryption "
                                "(SSE-S3 minimum, SSE-KMS for sensitive "
                                "data) so all new objects are encrypted "
                                "at rest automatically.",
                ))
        return findings


@register_aws_check
class S3VersioningCheck(BaseCheck):
    check_id = "AWS_S3_004"
    title = "S3 bucket without versioning enabled"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        buckets, s3 = _list_buckets(self.session)
        for b in buckets:
            name = b["Name"]
            v = s3.get_bucket_versioning(Bucket=name)
            if v.get("Status") != "Enabled":
                findings.append(Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.LOW,
                    category=Category.MISCONFIGURATION,
                    provider="aws",
                    resource_id=name,
                    resource_type="s3_bucket",
                    region="global",
                    description=f"Bucket '{name}' does not have versioning "
                                f"enabled, so accidental deletes/overwrites "
                                f"and ransomware-style object tampering "
                                f"cannot be rolled back.",
                    remediation="Enable versioning, and consider MFA "
                                "Delete for buckets holding critical data.",
                ))
        return findings
