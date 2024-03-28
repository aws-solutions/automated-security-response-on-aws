# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `SetS3LifecyclePolicy` remediation script"""

import boto3
from botocore.config import Config
from moto import mock_aws
from SetS3LifecyclePolicy import lambda_handler as remediation

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


@mock_aws
def test_set_lifecycle_policy():
    s3 = boto3.client("s3", config=BOTO_CONFIG)

    bucket_name = "test-bucket"
    event = {
        "BucketName": bucket_name,
        "TargetTransitionDays": 90,
        "TargetExpirationDays": 0,
        "TargetTransitionStorageClass": "STANDARD_IA",
    }

    # Create S3 bucket with no lifecycle policy
    s3.create_bucket(Bucket=bucket_name)

    remediation(event, {})

    lifecycle_config = s3.get_bucket_lifecycle_configuration(
        Bucket=bucket_name,
    )

    # Assert the rule is the one we set with the remediation script
    assert lifecycle_config["Rules"][0]["ID"] == "S3.13 Remediation Example"
    assert "Expiration" not in lifecycle_config["Rules"][0]


@mock_aws
def test_set_lifecycle_policy_with_expiration():
    s3 = boto3.client("s3", config=BOTO_CONFIG)

    bucket_name = "test-bucket"
    event = {
        "BucketName": bucket_name,
        "TargetTransitionDays": 90,
        "TargetExpirationDays": 90,
        "TargetTransitionStorageClass": "STANDARD_IA",
    }

    # Create S3 bucket with no lifecycle policy
    s3.create_bucket(Bucket=bucket_name)

    remediation(event, {})

    lifecycle_config = s3.get_bucket_lifecycle_configuration(
        Bucket=bucket_name,
    )

    # Assert the rule is the one we set with the remediation script
    assert lifecycle_config["Rules"][0]["ID"] == "S3.13 Remediation Example"
    assert "Expiration" in lifecycle_config["Rules"][0]
