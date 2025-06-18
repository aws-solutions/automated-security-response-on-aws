# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_secretsmanager():
    return boto3.client("secretsmanager", config=BOTO_CONFIG)


# Check if secret rotation is enabled on the secet.
def check_secret_rotation(secret_arn, secretsmanager_client):
    response = secretsmanager_client.describe_secret(SecretId=secret_arn)
    if "RotationEnabled" in response:
        if response["RotationEnabled"]:
            return True
    else:
        return False


def lambda_handler(event, _):
    secret_arn = event["SecretARN"]
    number_of_days = event["MaximumAllowedRotationFrequency"]

    secretsmanager = connect_to_secretsmanager()

    try:
        # Set rotation schedule following best practices
        secretsmanager.rotate_secret(
            SecretId=secret_arn,
            RotationRules={
                "AutomaticallyAfterDays": int(number_of_days),
            },
            RotateImmediately=False,
        )

        # Verify secret rotation is enabled.
        if check_secret_rotation(secret_arn, secretsmanager):
            return {
                "message": f"Enabled automatic secret rotation every {number_of_days} days with previously set rotation function.",
                "status": "Success",
            }
        else:
            raise RuntimeError(
                "Failed to set automatic rotation schedule. Please manually set rotation on the secret."
            )

    # If a Lambda function ARN is not associated, an exception will be thrown.
    except Exception as e:
        # Verify secret rotation is enabled.
        if check_secret_rotation(secret_arn, secretsmanager):
            return {
                "message": f"Enabled automatic secret rotation every {number_of_days} days with previously set function.",
                "status": "Success",
            }
        else:
            exit(f"Error when setting automatic rotation schedule: {str(e)}")
