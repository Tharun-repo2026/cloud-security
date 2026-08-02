"""
Generates sample_data/sample_report.json using the REAL Finding/report
code (not hand-written JSON) so the dashboard demo reflects the actual
data shape the scanner produces. Simulates a scan of a mid-size org
across all three providers.
"""
import sys
sys.path.insert(0, ".")

import random
from cloudsec_scanner.core.finding import Category, Finding, Severity
from cloudsec_scanner.core.report import build_report, save_json_report

random.seed(7)

findings = []

def add(check_id, title, sev, cat, provider, resource_id, resource_type, region, desc, remediation):
    findings.append(Finding(
        check_id=check_id, title=title, severity=sev, category=cat, provider=provider,
        resource_id=resource_id, resource_type=resource_type, region=region,
        description=desc, remediation=remediation,
    ))

# --- AWS ---
add("AWS_IAM_005", "Root account has active access keys", Severity.CRITICAL, Category.IAM, "aws",
    "root-account", "iam_root", "global",
    "The root account has one or more active access keys.",
    "Delete root access keys immediately; use IAM roles instead.")
add("AWS_S3_002", "S3 bucket is publicly accessible via ACL or bucket policy", Severity.CRITICAL, Category.MISCONFIGURATION, "aws",
    "prod-customer-uploads", "s3_bucket", "global",
    "Bucket 'prod-customer-uploads' policy grants public access per S3's policy-status evaluation.",
    "Review and tighten the bucket policy; remove wildcard Principals.")
add("AWS_NET_001", "Security group allows 0.0.0.0/0 ingress on a sensitive port", Severity.CRITICAL, Category.NETWORK, "aws",
    "sg-0a1b2c3d4e", "security_group", "us-east-1",
    "Security group 'db-access' allows inbound MySQL (port 3306) from 0.0.0.0/0.",
    "Restrict port 3306 to known IP ranges or a bastion/VPN.")
add("AWS_DATA_001", "RDS instance is publicly accessible", Severity.CRITICAL, Category.NETWORK, "aws",
    "arn:aws:rds:us-east-1:123456789012:db:prod-primary", "rds_instance", "us-east-1",
    "RDS instance 'prod-primary' has PubliclyAccessible=true.",
    "Set PubliclyAccessible to false; access via VPC-internal routes.")
add("AWS_IAM_003", "IAM policy grants wildcard Action and Resource (admin-equivalent)", Severity.CRITICAL, Category.IAM, "aws",
    "arn:aws:iam::123456789012:policy/legacy-full-access", "iam_policy", "global",
    "Policy 'legacy-full-access' allows Action:* on Resource:*.",
    "Scope the policy to least privilege.")
add("AWS_IAM_001", "IAM user has console access but no MFA device", Severity.HIGH, Category.IAM, "aws",
    "arn:aws:iam::123456789012:user/j.patel", "iam_user", "global",
    "IAM user 'j.patel' can sign in with a password but has no MFA device.",
    "Require MFA for all console users.")
add("AWS_S3_001", "S3 bucket without account/bucket-level Public Access Block", Severity.HIGH, Category.MISCONFIGURATION, "aws",
    "internal-logs-archive", "s3_bucket", "global",
    "Bucket 'internal-logs-archive' does not have all Public Access Block settings enabled.",
    "Enable all four Public Access Block settings.")
add("AWS_DATA_002", "RDS instance storage is not encrypted", Severity.HIGH, Category.ENCRYPTION, "aws",
    "arn:aws:rds:eu-west-1:123456789012:db:analytics-replica", "rds_instance", "eu-west-1",
    "RDS instance 'analytics-replica' does not have storage encryption enabled.",
    "Create an encrypted snapshot and restore to a new encrypted instance.")
add("AWS_SEC_001", "Lambda secrets-like env vars without KMS encryption", Severity.HIGH, Category.SECRETS, "aws",
    "arn:aws:lambda:us-east-1:123456789012:function:payment-webhook", "lambda_function", "us-east-1",
    "Function 'payment-webhook' has env vars named like secrets (STRIPE_SECRET_KEY) but no KMS key configured.",
    "Move secrets to AWS Secrets Manager or SSM Parameter Store.")
add("AWS_IAM_002", "IAM access key older than 90 days", Severity.MEDIUM, Category.IAM, "aws",
    "AKIA4EXAMPLE1234567", "iam_access_key", "global",
    "Access key AKIA4EXAMPLE1234567 for user 'ci-deploy-bot' is 214 days old.",
    "Rotate access keys at least every 90 days.")
add("AWS_S3_003", "S3 bucket without default server-side encryption", Severity.MEDIUM, Category.ENCRYPTION, "aws",
    "marketing-assets", "s3_bucket", "global",
    "Bucket 'marketing-assets' has no default encryption configuration.",
    "Enable default bucket encryption.")
add("AWS_NET_004", "VPC has no Flow Logs enabled", Severity.MEDIUM, Category.LOGGING, "aws",
    "vpc-0f9e8d7c6b", "vpc", "us-east-1",
    "VPC vpc-0f9e8d7c6b in us-east-1 has no Flow Logs.",
    "Enable VPC Flow Logs to CloudWatch Logs or S3.")
add("AWS_DATA_003", "EBS volume is not encrypted", Severity.MEDIUM, Category.ENCRYPTION, "aws",
    "vol-0123456789abcdef0", "ebs_volume", "us-west-2",
    "EBS volume vol-0123456789abcdef0 is unencrypted.",
    "Enable EBS encryption by default for the account/region.")
add("AWS_NET_003", "Default VPC still present", Severity.LOW, Category.NETWORK, "aws",
    "vpc-default01", "vpc", "ap-southeast-1",
    "Default VPC vpc-default01 exists in ap-southeast-1.",
    "Delete unused default VPCs or lock down their default security group.")
add("AWS_S3_004", "S3 bucket without versioning enabled", Severity.LOW, Category.MISCONFIGURATION, "aws",
    "terraform-state-backups", "s3_bucket", "global",
    "Bucket 'terraform-state-backups' does not have versioning enabled.",
    "Enable versioning to protect against accidental deletes.")
add("AWS_SEC_002", "Secrets Manager secret has rotation disabled", Severity.LOW, Category.SECRETS, "aws",
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds-Ab12Cd", "secretsmanager_secret", "us-east-1",
    "Secret 'db-creds' does not have automatic rotation enabled.",
    "Enable automatic rotation using a rotation Lambda.")

# --- Azure ---
add("AZURE_NET_001", "Network Security Group allows inbound from Internet on a sensitive port", Severity.CRITICAL, Category.NETWORK, "azure",
    "/subscriptions/xxx/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/prod-nsg",
    "network_security_group", "eastus",
    "NSG 'prod-nsg' rule 'allow-rdp-any' allows inbound RDP (port 3389) from the public internet.",
    "Restrict source to known IP ranges or use Azure Bastion.")
add("AZURE_STORAGE_001", "Storage account allows public blob access", Severity.HIGH, Category.MISCONFIGURATION, "azure",
    "/subscriptions/xxx/resourceGroups/data-rg/providers/Microsoft.Storage/storageAccounts/sharedassets001",
    "storage_account", "westeurope",
    "Storage account 'sharedassets001' has allowBlobPublicAccess enabled.",
    "Set allowBlobPublicAccess to false; use SAS tokens or Azure AD auth.")

# --- GCP ---
add("GCP_NET_001", "Firewall rule allows 0.0.0.0/0 ingress on a sensitive port", Severity.CRITICAL, Category.NETWORK, "gcp",
    "allow-ssh-all", "firewall_rule", "global",
    "Firewall rule 'allow-ssh-all' allows inbound SSH (22) from 0.0.0.0/0.",
    "Restrict source_ranges to known IPs, or use Identity-Aware Proxy for SSH.")
add("GCP_STORAGE_001", "GCS bucket grants public access (allUsers / allAuthenticatedUsers)", Severity.MEDIUM, Category.MISCONFIGURATION, "gcp",
    "gs://staging-build-artifacts", "gcs_bucket", "us-central1",
    "Bucket 'gs://staging-build-artifacts' grants role 'roles/storage.objectViewer' to allUsers.",
    "Remove allUsers/allAuthenticatedUsers bindings; use uniform bucket-level access.")

report = build_report(findings, provider="multi-cloud", account_id="demo-org", scan_duration_seconds=47.3)
save_json_report(report, "sample_data/sample_report.json")
print("wrote sample_data/sample_report.json")
print("posture score:", report["posture_score"])
print("total findings:", report["meta"]["total_findings"])
