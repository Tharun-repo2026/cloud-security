"""
Core data model for scan findings.

Every check across every provider (AWS/Azure/GCP) returns a list of
Finding objects. This is the one shape the rest of the system
(reporting, the dashboard, scoring) needs to understand.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]


class Category(str, Enum):
    IAM = "IAM"
    NETWORK = "NETWORK"
    MISCONFIGURATION = "MISCONFIGURATION"
    SECRETS = "SECRETS"
    ENCRYPTION = "ENCRYPTION"
    LOGGING = "LOGGING"


@dataclass
class Finding:
    check_id: str                 # stable id, e.g. "AWS_S3_001"
    title: str                    # short human title
    severity: Severity
    category: Category
    provider: str                 # "aws" | "azure" | "gcp"
    resource_id: str              # arn / resource id / name
    resource_type: str            # "s3_bucket", "security_group", ...
    region: str
    description: str              # what's wrong
    remediation: str              # how to fix it
    account_id: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d
