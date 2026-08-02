"""
Azure scanner.

Same plugin architecture as AWS: checks register themselves against
AZURE_REGISTRY and BaseProviderScanner runs all of them. Two checks
are fully implemented (storage public access, NSG open ports) to prove
the pattern end-to-end; add more by copying either class and pointing
it at a different azure-mgmt-* client.

Requires: azure-identity, azure-mgmt-storage, azure-mgmt-network
"""
from __future__ import annotations

from cloudsec_scanner.core.finding import Category, Finding, Severity
from cloudsec_scanner.core.scanner_base import (
    AZURE_REGISTRY,
    BaseCheck,
    BaseProviderScanner,
    register_azure_check,
)

SENSITIVE_PORTS = {"22": "SSH", "3389": "RDP", "1433": "MSSQL", "3306": "MySQL"}


class AzureSession:
    """Bundles an Azure credential with the subscription it scans."""

    def __init__(self, subscription_id: str):
        from azure.identity import DefaultAzureCredential

        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()


@register_azure_check
class StoragePublicAccessCheck(BaseCheck):
    check_id = "AZURE_STORAGE_001"
    title = "Storage account allows public blob access"
    provider = "azure"

    def run(self) -> list[Finding]:
        from azure.mgmt.storage import StorageManagementClient

        session: AzureSession = self.session
        client = StorageManagementClient(session.credential, session.subscription_id)
        findings = []
        for account in client.storage_accounts.list():
            if getattr(account, "allow_blob_public_access", False):
                findings.append(Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    category=Category.MISCONFIGURATION,
                    provider="azure",
                    resource_id=account.id,
                    resource_type="storage_account",
                    region=account.location,
                    description=f"Storage account '{account.name}' has "
                                f"allowBlobPublicAccess enabled, permitting "
                                f"anonymous container/blob access.",
                    remediation="Set allowBlobPublicAccess to false at the "
                                "storage account level and use SAS tokens "
                                "or Azure AD auth for controlled access.",
                    account_id=session.subscription_id,
                ))
        return findings


@register_azure_check
class NSGOpenPortCheck(BaseCheck):
    check_id = "AZURE_NET_001"
    title = "Network Security Group allows inbound from Internet on a sensitive port"
    provider = "azure"

    def run(self) -> list[Finding]:
        from azure.mgmt.network import NetworkManagementClient

        session: AzureSession = self.session
        client = NetworkManagementClient(session.credential, session.subscription_id)
        findings = []
        for nsg in client.network_security_groups.list_all():
            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue
                src = (rule.source_address_prefix or "").strip()
                if src not in ("*", "0.0.0.0/0", "Internet", "any"):
                    continue
                port_range = rule.destination_port_range or ""
                for port, name in SENSITIVE_PORTS.items():
                    if port == port_range or port_range == "*":
                        findings.append(Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=Severity.CRITICAL,
                            category=Category.NETWORK,
                            provider="azure",
                            resource_id=nsg.id,
                            resource_type="network_security_group",
                            region=nsg.location,
                            description=f"NSG '{nsg.name}' rule "
                                        f"'{rule.name}' allows inbound {name} "
                                        f"(port {port}) from the public "
                                        f"internet.",
                            remediation=f"Restrict source to known IP "
                                        f"ranges or use Azure Bastion "
                                        f"instead of exposing port {port} "
                                        f"directly.",
                            account_id=session.subscription_id,
                        ))
        return findings


class AzureScanner(BaseProviderScanner):
    provider = "azure"
    registry = AZURE_REGISTRY

    def __init__(self, subscription_id: str, categories: list[str] | None = None):
        super().__init__(session=AzureSession(subscription_id), categories=categories)
