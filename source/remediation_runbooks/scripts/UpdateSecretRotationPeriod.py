# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_secretsmanager():
    return boto3.client("secretsmanager", config=boto_config)


def lambda_handler(event, _):
    secret_arn = event["SecretARN"]
    max_days_since_rotation = event["MaxDaysSinceRotation"]

    secretsmanager = connect_to_secretsmanager()

    try:
        # Rotate secret and set rotation schedule
        secretsmanager.rotate_secret(
            SecretId=secret_arn,
            RotationRules={
                "AutomaticallyAfterDays": max_days_since_rotation,
            },
            RotateImmediately=True,
        )

        # Verify secret rotation schedule updated.
        response = secretsmanager.describe_secret(SecretId=secret_arn)

        if "RotationRules" in response:
            if (
                response["RotationRules"]["AutomaticallyAfterDays"]
                <= max_days_since_rotation
            ):
                return {
                    "message": f"Rotated secret and set rotation schedule to {max_days_since_rotation} days.",
                    "status": "Success",
                }
        else:
            return {
                "message": "Failed to rotate secret and set rotation schedule.",
                "status": "Failed",
            }

    # If secret was already rotated, an exception will be thrown.
    except Exception as e:
        # Verify secret rotation schedule updated.
        response = secretsmanager.describe_secret(SecretId=secret_arn)

        if "RotationRules" in response:
            if (
                response["RotationRules"]["AutomaticallyAfterDays"]
                <= max_days_since_rotation
            ):
                return {
                    "message": f"Set rotation schedule to {max_days_since_rotation} days. Secret is already being rotated.",
                    "status": "Success",
                }
        else:
            return {
                "message": f"Failed to rotate secret and set rotation schedule: {str(e)}",
                "status": "Failed",
            }
