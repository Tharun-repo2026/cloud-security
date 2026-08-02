"""AWS scanner orchestrator."""
from __future__ import annotations

import boto3

from cloudsec_scanner.core.scanner_base import AWS_REGISTRY, BaseProviderScanner
from cloudsec_scanner.providers.aws import checks  # noqa: F401  (registers checks)


class AWSScanner(BaseProviderScanner):
    provider = "aws"
    registry = AWS_REGISTRY

    def __init__(self, profile: str | None = None, region: str = "us-east-1",
                 categories: list[str] | None = None):
        session = boto3.Session(profile_name=profile, region_name=region)
        # sanity check credentials early with a cheap call
        sts = session.client("sts")
        self.account_id = sts.get_caller_identity()["Account"]
        super().__init__(session=session, categories=categories)
