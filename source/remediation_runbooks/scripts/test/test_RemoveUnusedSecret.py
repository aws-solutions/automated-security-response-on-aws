# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from RemoveUnusedSecret import lambda_handler as remediation

BOTO_CONFIG = Config(
    retries={"mode": "standard", "max_attempts": 10}, region_name="us-east-1"
)

# Example name and ARN for the Secrets Manager secret
SECRET_NAME = "test-secret"
SECRET_ARN = (
    f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{SECRET_NAME}-PyhdWC"
)

# Current date in the same format SecretsManager tracks LastAccessedDate
DATE_TODAY = datetime.now().replace(
    hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc
)

# Parameter for SecretsManager.3 control that specifies how many days a secret can be unused
UNUSED_FOR_DAYS = 90


def add_response_create_secret(stubber):
    # Add response to create_secret
    stubber.add_response(
        "create_secret",
        {
            "ARN": SECRET_ARN,
            "Name": SECRET_NAME,
        },
        {
            "Name": SECRET_NAME,
            "SecretString": "test-secret-value",
        },
    )


# =====================================================================================
# RemoveUnusedSecret SUCCESS
# =====================================================================================
def test_remove_unused_secret_success(mocker):
    # Setup client for Secrets Manager
    secretsmanager_client = boto3.client("secretsmanager", config=BOTO_CONFIG)
    stubber = Stubber(secretsmanager_client)

    # Add response to create_secret
    add_response_create_secret(stubber)

    # Add response to describe_secret for remediation script with LastAccessedDate > 90
    stubber.add_response(
        "describe_secret",
        {
            "ARN": SECRET_ARN,
            "LastAccessedDate": DATE_TODAY - timedelta(days=91),
        },
        {
            "SecretId": SECRET_ARN,
        },
    )

    # Add response to delete_secret for remediation script
    stubber.add_response(
        "delete_secret",
        {
            "DeletionDate": DATE_TODAY,
        },
        {
            "SecretId": SECRET_ARN,
            "RecoveryWindowInDays": 30,
        },
    )

    stubber.add_response(
        "describe_secret",
        {
            "ARN": SECRET_ARN,
            "DeletedDate": DATE_TODAY,
        },
        {
            "SecretId": SECRET_ARN,
        },
    )

    # Activate stubber
    stubber.activate()

    mocker.patch(
        "RemoveUnusedSecret.connect_to_secretsmanager",
        return_value=secretsmanager_client,
    )

    # Create test secret
    secret = secretsmanager_client.create_secret(
        Name="test-secret", SecretString="test-secret-value"
    )

    # Extract the ARN of the secret from response
    secret_arn = secret["ARN"]

    event = {
        "SecretARN": secret_arn,
        "UnusedForDays": UNUSED_FOR_DAYS,
    }

    # Execute the remediation script
    response = remediation(event, {})

    # Assert te remediation successfully deleted the secret
    assert response["status"] == "Success"

    # Describe the secret pending deletion
    deleted_secret = secretsmanager_client.describe_secret(SecretId=secret_arn)

    # Assert the secret is scheduled for deletion
    assert "DeletedDate" in deleted_secret

    # Deactivate stubber
    stubber.deactivate()


# =====================================================================================
# RemoveUnusedSecret FAILURE
# If secret has been accessed within the days specified by UNUSED_FOR_DAYS
# =====================================================================================
def test_remove_unused_secret_failure(mocker):
    # Setup client for Secrets Manager
    secretsmanager_client = boto3.client("secretsmanager", config=BOTO_CONFIG)
    stubber = Stubber(secretsmanager_client)

    # Add response to create_secret
    add_response_create_secret(stubber)

    # Add response to describe_secret for remediation script with LastAccessedDate < 90
    stubber.add_response(
        "describe_secret",
        {
            "ARN": SECRET_ARN,
            "LastAccessedDate": DATE_TODAY - timedelta(days=89),
        },
        {
            "SecretId": SECRET_ARN,
        },
    )

    # Activate stubber
    stubber.activate()

    mocker.patch(
        "RemoveUnusedSecret.connect_to_secretsmanager",
        return_value=secretsmanager_client,
    )

    # Create test secret
    secret = secretsmanager_client.create_secret(
        Name="test-secret", SecretString="test-secret-value"
    )

    # Extract the ARN of the secret from response
    secret_arn = secret["ARN"]

    event = {
        "SecretARN": secret_arn,
        "UnusedForDays": UNUSED_FOR_DAYS,
    }

    # Execute the remediation script
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        remediation(event, {})

    # Assert the remediation script fails
    assert pytest_wrapped_e.type == SystemExit

    assert "cannot be deleted because it has been accessed within the past" in str(
        pytest_wrapped_e.value
    )

    # Deactivate stubber
    stubber.deactivate()
