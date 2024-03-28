# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime, timezone

import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

# Current date in the same format SecretsManager tracks LastAccessedDate
DATE_TODAY = datetime.now().replace(
    hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc
)


def connect_to_secretsmanager():
    return boto3.client("secretsmanager", config=BOTO_CONFIG)


def lambda_handler(event, _):
    secret_arn = event["SecretARN"]
    unused_for_days = event["UnusedForDays"]

    secretsmanager = connect_to_secretsmanager()

    # Describe the secret
    response = secretsmanager.describe_secret(SecretId=secret_arn)

    # Confirm the secret has been unused for more days than UnusedForDays parameter specifies
    if "LastAccessedDate" in response and (
        DATE_TODAY - response["LastAccessedDate"]
    ).days > int(unused_for_days):
        # Delete the secret, with 30 day recovery window
        response = secretsmanager.delete_secret(
            SecretId=secret_arn,
            RecoveryWindowInDays=30,
        )

        # Confirm secret was scheduled for deletion
        if "DeletionDate" in response:
            return {
                "message": "Deleted the unused secret.",
                "status": "Success",
            }
        else:
            exit(f"Failed to delete the unused secret: {secret_arn}")

    exit(
        f"The secret {secret_arn} cannot be deleted because it has been accessed within the past {unused_for_days} days."
    )
