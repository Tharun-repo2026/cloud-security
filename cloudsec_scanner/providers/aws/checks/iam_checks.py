"""AWS IAM checks: identity and access hygiene."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudsec_scanner.core.finding import Category, Finding, Severity
from cloudsec_scanner.core.scanner_base import BaseCheck, register_aws_check


@register_aws_check
class IAMUsersWithoutMFACheck(BaseCheck):
    check_id = "AWS_IAM_001"
    title = "IAM user has console access but no MFA device"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        iam = self.session.client("iam")
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                try:
                    iam.get_login_profile(UserName=uname)
                    has_console = True
                except ClientError:
                    has_console = False
                if not has_console:
                    continue
                mfa = iam.list_mfa_devices(UserName=uname)["MFADevices"]
                if not mfa:
                    findings.append(Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        category=Category.IAM,
                        provider="aws",
                        resource_id=user["Arn"],
                        resource_type="iam_user",
                        region="global",
                        description=f"IAM user '{uname}' can sign in to the "
                                    f"console with a password but has no "
                                    f"MFA device registered.",
                        remediation="Require MFA for all console users "
                                    "(virtual, hardware, or FIDO2), and "
                                    "enforce it via an IAM policy condition.",
                    ))
        return findings


@register_aws_check
class IAMStaleAccessKeysCheck(BaseCheck):
    check_id = "AWS_IAM_002"
    title = "IAM access key older than 90 days"
    provider = "aws"
    MAX_AGE_DAYS = 90

    def run(self) -> list[Finding]:
        findings = []
        iam = self.session.client("iam")
        now = datetime.now(timezone.utc)
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                keys = iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] != "Active":
                        continue
                    age = (now - key["CreateDate"]).days
                    if age > self.MAX_AGE_DAYS:
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            category=Category.IAM,
                            provider="aws",
                            resource_id=key["AccessKeyId"],
                            resource_type="iam_access_key",
                            region="global",
                            description=f"Access key {key['AccessKeyId']} for "
                                        f"user '{uname}' is {age} days old.",
                            remediation="Rotate access keys at least every "
                                        "90 days, or replace long-lived keys "
                                        "with short-lived STS credentials / "
                                        "IAM roles entirely.",
                            evidence={"age_days": age},
                        ))
        return findings


@register_aws_check
class IAMOverprivilegedPolicyCheck(BaseCheck):
    check_id = "AWS_IAM_003"
    title = "IAM policy grants wildcard Action and Resource (admin-equivalent)"
    provider = "aws"

    def run(self) -> list[Finding]:
        findings = []
        iam = self.session.client("iam")
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):  # customer-managed only
            for policy in page["Policies"]:
                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                except ClientError:
                    continue
                doc = version["PolicyVersion"]["Document"]
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    actions = [actions] if isinstance(actions, str) else actions
                    resources = [resources] if isinstance(resources, str) else resources
                    if "*" in actions and "*" in resources:
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.CRITICAL,
                            category=Category.IAM,
                            provider="aws",
                            resource_id=policy["Arn"],
                            resource_type="iam_policy",
                            region="global",
                            description=f"Policy '{policy['PolicyName']}' has "
                                        f"a statement allowing Action:* on "
                                        f"Resource:*, equivalent to "
                                        f"AdministratorAccess.",
                            remediation="Scope the policy to the specific "
                                        "actions and resource ARNs the "
                                        "attached identity actually needs "
                                        "(least privilege).",
                        ))
                        break
        return findings


@register_aws_check
class IAMPasswordPolicyCheck(BaseCheck):
    check_id = "AWS_IAM_004"
    title = "Account password policy is weak or missing"
    provider = "aws"

    def run(self) -> list[Finding]:
        iam = self.session.client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return [Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    category=Category.IAM,
                    provider="aws",
                    resource_id="account-password-policy",
                    resource_type="iam_password_policy",
                    region="global",
                    description="No account password policy is configured; "
                                "the AWS default (very permissive) applies.",
                    remediation="Set a password policy requiring length >= "
                                "14, a mix of character types, and password "
                                "reuse prevention.",
                )]
            raise
        issues = []
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("minimum length is under 14 characters")
        if not policy.get("RequireSymbols"):
            issues.append("symbols are not required")
        if not policy.get("RequireNumbers"):
            issues.append("numbers are not required")
        if policy.get("PasswordReusePrevention", 0) < 3:
            issues.append("password reuse prevention is weak or unset")
        if not issues:
            return []
        return [Finding(
            check_id=self.check_id,
            title=self.title,
            severity=Severity.MEDIUM,
            category=Category.IAM,
            provider="aws",
            resource_id="account-password-policy",
            resource_type="iam_password_policy",
            region="global",
            description="Account password policy is weak: " + "; ".join(issues) + ".",
            remediation="Tighten the password policy: length >= 14, require "
                        "symbols and numbers, and set password reuse "
                        "prevention to at least 3.",
        )]


@register_aws_check
class IAMRootAccessKeysCheck(BaseCheck):
    check_id = "AWS_IAM_005"
    title = "Root account has active access keys"
    provider = "aws"

    def run(self) -> list[Finding]:
        iam = self.session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            return [Finding(
                check_id=self.check_id,
                title=self.title,
                severity=Severity.CRITICAL,
                category=Category.IAM,
                provider="aws",
                resource_id="root-account",
                resource_type="iam_root",
                region="global",
                description="The root account has one or more active access "
                            "keys. Root keys have unrestricted, "
                            "un-scopeable access to the account.",
                remediation="Delete root access keys immediately. Use IAM "
                            "roles/users with least-privilege policies for "
                            "all programmatic access, and enable MFA on "
                            "root.",
            )]
        return []
