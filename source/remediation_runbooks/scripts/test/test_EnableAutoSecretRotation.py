# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from EnableAutoSecretRotation import lambda_handler as remediation

BOTO_CONFIG = Config(
    retries={"mode": "standard", "max_attempts": 10}, region_name="us-east-1"
)

# Example name and ARN for the Secrets Manager secret
SECRET_NAME = "test-secret"
SECRET_ARN = (
    f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{SECRET_NAME}-PyhdWC"
)

# Example name and ARN for IAM role used for Lambda rotation function
ROLE_NAME = "rotation_function_role"
ROLE_ARN = f"arn:aws:iam::123456789012:role/service-role/{ROLE_NAME}"

# Example role trust policy for the Lambda rotation function
ROLE_TRUST_POLICY = '{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Principal": { "Service": "lambda.amazonaws.com" }, "Action": "sts:AssumeRole" } ] }'

# Example name and ARN for Lambda rotation function
FUNCTION_NAME = "rotation_function"
FUNCTION_ARN = f"arn:aws:lambda:us-east-1:123456789012:function:{FUNCTION_NAME}"


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
# EnableAutoSecretRotation SUCCESS
# =====================================================================================
def test_enable_rotation_success(mocker):
    # Setup client for Secrets Manager
    secretsmanager_client = boto3.client("secretsmanager", config=BOTO_CONFIG)
    stub_secretsmanager = Stubber(secretsmanager_client)

    # Setup client for IAM
    iam_client = boto3.client("iam", config=BOTO_CONFIG)
    stub_iam = Stubber(iam_client)

    # Setup client for Lambda
    lambda_client = boto3.client("lambda", config=BOTO_CONFIG)
    stub_lambda = Stubber(lambda_client)

    # Add response to create_secret
    add_response_create_secret(stub_secretsmanager)

    # Add response to create IAM execution role for Lambda rotation function
    stub_iam.add_response(
        "create_role",
        {
            "Role": {
                "Path": "/service-role/",
                "RoleName": ROLE_NAME,
                "RoleId": "AAAAAAAAAAAAAAAA",
                "Arn": ROLE_ARN,
                "CreateDate": "2022-01-01T00:00:00Z",
            },
        },
        {
            "RoleName": ROLE_NAME,
            "AssumeRolePolicyDocument": ROLE_TRUST_POLICY,
        },
    )

    # Add response to create fake Lambda rotation function
    stub_lambda.add_response(
        "create_function",
        {
            "FunctionName": FUNCTION_NAME,
        },
        {
            "FunctionName": FUNCTION_NAME,
            "Role": ROLE_ARN,
            "Runtime": "python3.11",
            "Code": {"ZipFile": b"0"},
        },
    )

    # Add response to setup automatic rotation with fake Lambda function
    stub_secretsmanager.add_response(
        "rotate_secret",
        {
            "ARN": SECRET_ARN,
            "Name": SECRET_NAME,
        },
        {
            "SecretId": SECRET_ARN,
            "RotationLambdaARN": FUNCTION_ARN,
            "RotationRules": {
                "AutomaticallyAfterDays": 90,
            },
            "RotateImmediately": False,
        },
    )

    # Add response to cancel automatic rotation
    stub_secretsmanager.add_response(
        "cancel_rotate_secret",
        {
            "ARN": SECRET_ARN,
        },
        {
            "SecretId": SECRET_ARN,
        },
    )

    # Add response to describe secret with rotation disabled
    stub_secretsmanager.add_response(
        "describe_secret",
        {
            "ARN": SECRET_ARN,
            "RotationEnabled": False,
            "RotationLambdaARN": FUNCTION_ARN,
            "RotationRules": {
                "AutomaticallyAfterDays": 90,
            },
        },
        {
            "SecretId": SECRET_ARN,
        },
    )

    # Add response to set automatic rotation for remediation script
    stub_secretsmanager.add_response(
        "rotate_secret",
        {
            "ARN": SECRET_ARN,
            "Name": SECRET_NAME,
        },
        {
            "SecretId": SECRET_ARN,
            "RotationRules": {
                "AutomaticallyAfterDays": 90,
            },
            "RotateImmediately": False,
        },
    )

    # Add response to describe secret with rotation enabled for remediation script
    stub_secretsmanager.add_response(
        "describe_secret",
        {
            "ARN": SECRET_ARN,
            "RotationEnabled": True,
            "RotationLambdaARN": FUNCTION_ARN,
            "RotationRules": {
                "AutomaticallyAfterDays": 90,
            },
        },
        {
            "SecretId": SECRET_ARN,
        },
    )

    # Activate stubbers
    stub_secretsmanager.activate()
    stub_iam.activate()
    stub_lambda.activate()

    mocker.patch(
        "EnableAutoSecretRotation.connect_to_secretsmanager",
        return_value=secretsmanager_client,
    )

    # Create test secret without automatic rotation
    secretsmanager_client.create_secret(
        Name="test-secret",
        SecretString="test-secret-value",
    )

    # Create IAM execution role for Lambda rotation function
    iam_client.create_role(
        RoleName=ROLE_NAME,
        AssumeRolePolicyDocument=ROLE_TRUST_POLICY,
    )

    # Create fake Lambda rotation function
    lambda_client.create_function(
        FunctionName=FUNCTION_NAME,
        Role=ROLE_ARN,
        Runtime="python3.11",
        Code={
            "ZipFile": b"0",
        },
    )

    # Setup automatic rotation with fake Lambda function
    secretsmanager_client.rotate_secret(
        SecretId=SECRET_ARN,
        RotationLambdaARN=FUNCTION_ARN,
        RotationRules={
            "AutomaticallyAfterDays": 90,
        },
        RotateImmediately=False,
    )

    # Cancel automatic rotation
    secretsmanager_client.cancel_rotate_secret(SecretId=SECRET_ARN)

    # Describe secret with rotation disabled
    secret = secretsmanager_client.describe_secret(SecretId=SECRET_ARN)

    # Assert automatic rotation is disabled
    assert "RotationEnabled" in secret
    assert not secret["RotationEnabled"]

    # Run remediation script
    event = {"SecretARN": SECRET_ARN, "MaximumAllowedRotationFrequency": 90}
    response = remediation(event, {})

    assert response == {
        "message": "Enabled automatic secret rotation every 90 days with previously set rotation function.",
        "status": "Success",
    }

    stub_secretsmanager.deactivate()
    stub_iam.deactivate()
    stub_lambda.deactivate()


# =====================================================================================
# EnableAutoSecretRotation FAILURE
# =====================================================================================
def test_enable_rotation_failure(mocker):
    secretsmanager_client = boto3.client("secretsmanager", config=BOTO_CONFIG)
    stub_secretsmanager = Stubber(secretsmanager_client)

    # Add response to create_secret
    add_response_create_secret(stub_secretsmanager)

    # Add response to describe_secret
    stub_secretsmanager.add_response(
        "describe_secret",
        {
            "ARN": SECRET_ARN,
            "Name": SECRET_NAME,
        },
        {
            "SecretId": SECRET_ARN,
        },
    )

    # Add error response to describe_secret
    stub_secretsmanager.add_client_error(
        "describe_secret",
        "InvalidRequestException",
        "No Lambda rotation function ARN is associated with this secret.",
    )

    # Activate stubber
    stub_secretsmanager.activate()

    mocker.patch(
        "EnableAutoSecretRotation.connect_to_secretsmanager",
        return_value=secretsmanager_client,
    )

    # Create test secret without automatic rotation
    secretsmanager_client.create_secret(
        Name="test-secret", SecretString="test-secret-value"
    )

    # Describe test secret
    secret = secretsmanager_client.describe_secret(SecretId=SECRET_ARN)

    # Assert secret rotation has never been enabled
    assert "RotationEnabled" not in secret

    # Run remediation script
    event = {"SecretARN": SECRET_ARN, "MaximumAllowedRotationFrequency": 90}
    with pytest.raises(Exception) as pytest_wrapped_e:
        remediation(event, {})

    # Assert remediation script fails because no Lambda function was provided.
    assert (
        pytest_wrapped_e.type
        == secretsmanager_client.exceptions.InvalidRequestException
    )
    assert "No Lambda rotation function ARN is associated with this secret." in str(
        pytest_wrapped_e.value
    )

    stub_secretsmanager.deactivate()
