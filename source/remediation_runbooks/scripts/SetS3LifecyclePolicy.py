# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_s3():
    return boto3.client("s3", config=BOTO_CONFIG)


def lambda_handler(event, _):
    bucket_name = event["BucketName"]
    target_transition_days = event["TargetTransitionDays"]
    target_expiration_days = event["TargetExpirationDays"]
    target_transition_storage_class = event["TargetTransitionStorageClass"]
    rule_id = "S3.13 Remediation Example"
    s3 = connect_to_s3()

    lifecycle_policy = {}
    if target_expiration_days != 0:
        lifecycle_policy = {
            "Rules": [
                {
                    "ID": rule_id,
                    "Status": "Enabled",
                    "Expiration": {
                        "Days": target_expiration_days,
                    },
                    "Transitions": [
                        {
                            "Days": target_transition_days,
                            "StorageClass": target_transition_storage_class,
                        },
                    ],
                    "Filter": {
                        "ObjectSizeGreaterThan": 131072,
                    },
                },
            ],
        }
    else:
        lifecycle_policy = {
            "Rules": [
                {
                    "ID": rule_id,
                    "Status": "Enabled",
                    "Transitions": [
                        {
                            "Days": target_transition_days,
                            "StorageClass": target_transition_storage_class,
                        },
                    ],
                    "Filter": {
                        "ObjectSizeGreaterThan": 131072,
                    },
                },
            ],
        }

    # Set example lifecycle policy
    # Moves objects larger than 128 KB to Intelligent Tiering storage class after 30 days
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket_name, LifecycleConfiguration=lifecycle_policy
    )

    # Get new lifecycle configuration
    lifecycle_config = s3.get_bucket_lifecycle_configuration(
        Bucket=bucket_name,
    )

    if lifecycle_config["Rules"][0]["ID"] == rule_id:
        return {
            "message": "Successfully set example S3 lifecycle policy. Review and update as needed.",
            "status": "Success",
        }

    else:
        raise RuntimeError(
            "Failed to set S3 lifecycle policy. Lifecycle rule ID did not match 'S3.13 Remediation Example'"
        )
