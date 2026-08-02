"""
GCP scanner.

Same plugin architecture as AWS/Azure. Two checks are fully implemented
(public GCS buckets, open firewall rules) to prove the pattern
end-to-end; add more by copying either class and pointing it at a
different google-cloud-* client.

Requires: google-cloud-storage, google-cloud-compute
"""
from __future__ import annotations

from cloudsec_scanner.core.finding import Category, Finding, Severity
from cloudsec_scanner.core.scanner_base import (
    GCP_REGISTRY,
    BaseCheck,
    BaseProviderScanner,
    register_gcp_check,
)

SENSITIVE_PORTS = {"22": "SSH", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL"}


class GCPSession:
    def __init__(self, project_id: str):
        self.project_id = project_id


@register_gcp_check
class GCSPublicBucketCheck(BaseCheck):
    check_id = "GCP_STORAGE_001"
    title = "GCS bucket grants public access (allUsers / allAuthenticatedUsers)"
    provider = "gcp"

    def run(self) -> list[Finding]:
        from google.cloud import storage

        session: GCPSession = self.session
        client = storage.Client(project=session.project_id)
        findings = []
        for bucket in client.list_buckets():
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    findings.append(Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=Severity.CRITICAL,
                        category=Category.MISCONFIGURATION,
                        provider="gcp",
                        resource_id=f"gs://{bucket.name}",
                        resource_type="gcs_bucket",
                        region=bucket.location or "unknown",
                        description=f"Bucket 'gs://{bucket.name}' grants "
                                    f"role '{binding.get('role')}' to "
                                    f"{'allUsers' if 'allUsers' in members else 'allAuthenticatedUsers'}, "
                                    f"i.e. the public internet.",
                        remediation="Remove allUsers/allAuthenticatedUsers "
                                    "bindings and use uniform bucket-level "
                                    "access with specific IAM principals.",
                        account_id=session.project_id,
                    ))
        return findings


@register_gcp_check
class FirewallOpenPortCheck(BaseCheck):
    check_id = "GCP_NET_001"
    title = "Firewall rule allows 0.0.0.0/0 ingress on a sensitive port"
    provider = "gcp"

    def run(self) -> list[Finding]:
        from google.cloud import compute_v1

        session: GCPSession = self.session
        client = compute_v1.FirewallsClient()
        findings = []
        for rule in client.list(project=session.project_id):
            if rule.direction != "INGRESS":
                continue
            if "0.0.0.0/0" not in list(rule.source_ranges or []):
                continue
            for allowed in rule.allowed or []:
                ports = list(allowed.ports) if allowed.ports else ["*"]
                for port_spec in ports:
                    port = port_spec.split("-")[0]
                    if port in SENSITIVE_PORTS or port_spec == "*":
                        name = SENSITIVE_PORTS.get(port, "all ports")
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.CRITICAL,
                            category=Category.NETWORK,
                            provider="gcp",
                            resource_id=rule.name,
                            resource_type="firewall_rule",
                            region="global",
                            description=f"Firewall rule '{rule.name}' allows "
                                        f"inbound {name} ({port_spec}) from "
                                        f"0.0.0.0/0.",
                            remediation="Restrict source_ranges to known "
                                        "IPs, or use Identity-Aware Proxy "
                                        "for SSH/RDP instead of open "
                                        "firewall rules.",
                            account_id=session.project_id,
                        ))
        return findings


class GCPScanner(BaseProviderScanner):
    provider = "gcp"
    registry = GCP_REGISTRY

    def __init__(self, project_id: str, categories: list[str] | None = None):
        super().__init__(session=GCPSession(project_id), categories=categories)
