# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.config import Config
from moto import mock_aws
from UpdateSecretRotationPeriod import lambda_handler as remediation

BOTO_CONFIG = Config(
    retries={"mode": "standard", "max_attempts": 10}, region_name="us-east-1"
)


@mock_aws
def test_rotate_secret():
    secretsmanager = boto3.client("secretsmanager", config=BOTO_CONFIG)

    # Create test secret
    secret = secretsmanager.create_secret(
        Name="test-secret", SecretString="test-secret-value"
    )

    event = {"SecretARN": secret["ARN"], "MaxDaysSinceRotation": 90}

    # Set a rotation period longer than 90 days
    secretsmanager.rotate_secret(
        SecretId=secret["ARN"],
        RotationRules={
            "AutomaticallyAfterDays": 100,
        },
        RotateImmediately=False,
    )

    # Verify secret rotation is a value greater than 90 days
    original_secret = secretsmanager.describe_secret(SecretId=secret["ARN"])

    assert original_secret["RotationRules"]["AutomaticallyAfterDays"] > 90

    # Execute remediation
    remediation(event, {})

    # Verify secret rotation is scheduled for at least every 90 days
    secret_updated = secretsmanager.describe_secret(SecretId=secret["ARN"])

    assert secret_updated["RotationRules"]["AutomaticallyAfterDays"] <= 90
