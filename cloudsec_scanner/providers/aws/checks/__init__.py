"""
Importing this package triggers every AWS check module to register
itself against AWS_REGISTRY via the @register_aws_check decorator.
"""
from cloudsec_scanner.providers.aws.checks import (  # noqa: F401
    data_checks,
    iam_checks,
    network_checks,
    s3_checks,
    secrets_checks,
)
