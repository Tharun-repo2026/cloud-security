"""
Test the scanner WITHOUT a real AWS account.

This uses `moto`, a library that intercepts boto3 API calls and answers
them with an in-memory fake AWS -- no network calls, no real account,
no cost, no credit card. We deliberately create a few misconfigured
fake resources (a public S3 bucket, a wide-open security group, a
non-MFA IAM user) and then run the REAL AWSScanner against them.

This proves the actual check logic works end-to-end, not just the
report/dashboard plumbing (that's what generate_sample_report.py tests).

Usage:
    pip install moto
    python test_with_fake_aws.py
"""
import sys
sys.path.insert(0, ".")

import boto3
from moto import mock_aws

from cloudsec_scanner.core.report import build_report, save_json_report, save_html_report


@mock_aws
def run():
    # ---- build a deliberately insecure fake AWS account ----
    region = "us-east-1"
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam", region_name=region)

    # 1. A public S3 bucket (no Public Access Block, no encryption)
    s3.create_bucket(Bucket="fake-public-uploads")

    # 2. A private, well-configured bucket for contrast
    s3.create_bucket(Bucket="fake-secure-backups")
    s3.put_bucket_encryption(
        Bucket="fake-secure-backups",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_public_access_block(
        Bucket="fake-secure-backups",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(
        Bucket="fake-secure-backups", VersioningConfiguration={"Status": "Enabled"}
    )

    # 3. A wide-open security group (SSH from anywhere)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(
        GroupName="fake-open-ssh", Description="test", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    # 4. An IAM user with console access and no MFA
    iam.create_user(UserName="fake-risky-user")
    iam.create_login_profile(UserName="fake-risky-user", Password="Temp1234!")

    print("Fake AWS account built:")
    print("  - 1 public S3 bucket, 1 properly-secured S3 bucket")
    print("  - 1 security group open to the world on SSH")
    print("  - 1 IAM console user with no MFA")
    print()

    # ---- now run the REAL scanner against this fake account ----
    from cloudsec_scanner.providers.aws.scanner import AWSScanner
    from cloudsec_scanner.providers.aws.checks import network_checks, secrets_checks, data_checks

    # Real AWS accounts have a default VPC in every region, and this
    # scanner checks every region -- which is correct behavior, but
    # produces ~17 near-duplicate "default VPC" findings in a demo.
    # Pin region-spanning checks to just us-east-1 here so the output
    # is readable; remove this in a real scan.
    network_checks._all_regions = lambda session: [region]
    secrets_checks._all_regions = lambda session: [region]
    data_checks._all_regions = lambda session: [region]

    scanner = AWSScanner(region=region)
    print(f"Running all {len(scanner.registry)} registered AWS checks...")
    findings = scanner.scan()

    report = build_report(findings, provider="aws", account_id=scanner.account_id)
    save_json_report(report, "test_report.json")
    save_html_report(report, "test_report.html")

    print()
    print(f"Posture score: {report['posture_score']}/100")
    print(f"Total findings: {len(findings)}")
    print()
    for f in findings:
        print(f"  [{f.severity.value:8}] {f.title} -> {f.resource_id}")
    print()
    print("Full reports written: test_report.json, test_report.html")


if __name__ == "__main__":
    run()
