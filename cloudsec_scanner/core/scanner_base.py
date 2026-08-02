"""
Plugin architecture.

Every check (AWS, Azure, GCP) is a small class registered against a
provider-specific registry. This is what makes the scanner extensible:
adding a new check for a new provider means writing one class and
decorating it -- nothing else in the system needs to change.
"""
from __future__ import annotations

import abc
import logging
from typing import Callable

from cloudsec_scanner.core.finding import Finding

logger = logging.getLogger("cloudsec_scanner")


class BaseCheck(abc.ABC):
    """One security check against one provider."""

    check_id: str
    title: str
    provider: str

    def __init__(self, session):
        # `session` is whatever provider-authenticated client/session
        # the scanner was constructed with (boto3.Session, Azure
        # credential+subscription, GCP client, ...).
        self.session = session

    @abc.abstractmethod
    def run(self) -> list[Finding]:
        """Execute the check and return zero or more Findings."""
        raise NotImplementedError

    def safe_run(self) -> list[Finding]:
        """Run the check, never let one bad check crash the whole scan."""
        try:
            return self.run()
        except Exception as exc:  # noqa: BLE001 - intentional broad catch
            logger.warning("check %s failed: %s", self.check_id, exc)
            return []


class CheckRegistry:
    """Per-provider registry of check classes."""

    def __init__(self, provider: str):
        self.provider = provider
        self._checks: dict[str, type[BaseCheck]] = {}

    def register(self, check_cls: type[BaseCheck]) -> type[BaseCheck]:
        self._checks[check_cls.check_id] = check_cls
        return check_cls

    def all(self) -> list[type[BaseCheck]]:
        return list(self._checks.values())

    def __len__(self) -> int:
        return len(self._checks)


AWS_REGISTRY = CheckRegistry("aws")
AZURE_REGISTRY = CheckRegistry("azure")
GCP_REGISTRY = CheckRegistry("gcp")


def register_aws_check(cls: type[BaseCheck]) -> type[BaseCheck]:
    return AWS_REGISTRY.register(cls)


def register_azure_check(cls: type[BaseCheck]) -> type[BaseCheck]:
    return AZURE_REGISTRY.register(cls)


def register_gcp_check(cls: type[BaseCheck]) -> type[BaseCheck]:
    return GCP_REGISTRY.register(cls)


class BaseProviderScanner(abc.ABC):
    """Orchestrates running every registered check for one provider."""

    provider: str
    registry: CheckRegistry

    def __init__(self, session, categories: list[str] | None = None):
        self.session = session
        self.categories = categories  # None => run everything

    def scan(self, progress_cb: Callable[[str], None] | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for check_cls in self.registry.all():
            if progress_cb:
                progress_cb(check_cls.check_id)
            check = check_cls(self.session)
            findings.extend(check.safe_run())
        return findings
