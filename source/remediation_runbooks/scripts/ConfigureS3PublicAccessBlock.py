# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from time import sleep
from typing import Optional, TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


class PublicAccessConfiguration(TypedDict):
    BlockPublicAcls: bool
    IgnorePublicAcls: bool
    BlockPublicPolicy: bool
    RestrictPublicBuckets: bool


class ValidateBucketPublicAccessBlockResponse(TypedDict):
    Message: str
    Valid: bool
    PublicAccessConfig: Optional[PublicAccessConfiguration]


class BucketEvent(TypedDict):
    Bucket: str
    RestrictPublicBuckets: bool
    BlockPublicAcls: bool
    IgnorePublicAcls: bool
    BlockPublicPolicy: bool


class AccountEvent(TypedDict):
    AccountId: str
    RestrictPublicBuckets: bool
    BlockPublicAcls: bool
    IgnorePublicAcls: bool
    BlockPublicPolicy: bool


class HandlerResponse(TypedDict):
    Message: str
    Status: str
    PublicAccessConfig: Optional[PublicAccessConfiguration]


def connect_to_service(service):
    return boto3.client(service, config=boto_config)


def handle_account(event: AccountEvent, _) -> HandlerResponse:
    """
    Configures the S3 account-level public access block.
    """
    try:
        account_id = event["AccountId"]
        public_access_block_config = {
            "BlockPublicAcls": event["BlockPublicAcls"],
            "IgnorePublicAcls": event["IgnorePublicAcls"],
            "BlockPublicPolicy": event["BlockPublicPolicy"],
            "RestrictPublicBuckets": event["RestrictPublicBuckets"],
        }
        put_account_public_access_block(account_id, public_access_block_config)

        valid_account_public_access_block = validate_account_public_access_block(
            account_id, public_access_block_config
        )

        if valid_account_public_access_block["Valid"]:
            return {
                "Message": f"Account {account_id} public access block configuration successfully set.",
                "Status": "Success",
                "PublicAccessConfig": valid_account_public_access_block[
                    "PublicAccessConfig"
                ],
            }
        else:
            expected_config = public_access_block_config
            return {
                "Message": f"Account {account_id} public access block configuration does not match with parameters "
                f"provided. \nExpected: {str(expected_config)}",
                "Status": "Failed",
                "PublicAccessConfig": None,
            }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error configuring public access block for account: {str(e)}"
        )


def handle_s3_bucket(event: BucketEvent, _) -> HandlerResponse:
    """
    Configures the public access block for an S3 bucket.
    """
    try:
        bucket = event["Bucket"]
        public_access_block_config = {
            "BlockPublicAcls": event["BlockPublicAcls"],
            "IgnorePublicAcls": event["IgnorePublicAcls"],
            "BlockPublicPolicy": event["BlockPublicPolicy"],
            "RestrictPublicBuckets": event["RestrictPublicBuckets"],
        }
        put_s3_bucket_public_access_block(bucket, public_access_block_config)

        valid_bucket_public_access_block = validate_bucket_public_access_block(
            bucket, public_access_block_config
        )

        if valid_bucket_public_access_block["Valid"]:
            return {
                "Message": f"Bucket {bucket} public access block configuration successfully set.",
                "Status": "Success",
                "PublicAccessConfig": valid_bucket_public_access_block[
                    "PublicAccessConfig"
                ],
            }
        else:
            actual_config = valid_bucket_public_access_block["PublicAccessConfig"]
            expected_config = public_access_block_config
            return {
                "Message": f"Bucket {bucket} public access block configuration does not match with parameters provided."
                f"\nExpected: {str(expected_config)}\nActual: {str(actual_config)}",
                "Status": "Failed",
                "PublicAccessConfig": actual_config,
            }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error configuring public access block for S3 Bucket: {str(e)}"
        )


def put_account_public_access_block(
    account_id: str,
    public_access_block_config: PublicAccessConfiguration,
) -> None:
    s3_client = connect_to_service("s3control")
    try:
        s3_client.put_public_access_block(
            AccountId=account_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": public_access_block_config["BlockPublicAcls"],
                "IgnorePublicAcls": public_access_block_config["IgnorePublicAcls"],
                "BlockPublicPolicy": public_access_block_config["BlockPublicPolicy"],
                "RestrictPublicBuckets": public_access_block_config[
                    "RestrictPublicBuckets"
                ],
            },
        )
    except Exception as e:
        raise RuntimeError(
            f"Encountered error putting public access block on account {account_id}: {str(e)}"
        )


def put_s3_bucket_public_access_block(
    bucket_name: str,
    public_access_block_config: PublicAccessConfiguration,
) -> None:
    s3_client = connect_to_service("s3")
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": public_access_block_config["BlockPublicAcls"],
                "IgnorePublicAcls": public_access_block_config["IgnorePublicAcls"],
                "BlockPublicPolicy": public_access_block_config["BlockPublicPolicy"],
                "RestrictPublicBuckets": public_access_block_config[
                    "RestrictPublicBuckets"
                ],
            },
        )
    except Exception as e:
        raise RuntimeError(
            f"Encountered error putting public access block on bucket {bucket_name}: {str(e)}"
        )


def validate_account_public_access_block(
    account_id,
    expected_public_access_block_config,
) -> ValidateBucketPublicAccessBlockResponse:
    s3control_client = boto3.client("s3control")
    wait_time = 30
    max_time = 480
    max_retries = max_time // wait_time
    try:
        for _ in range(max_retries):
            sleep(wait_time)

            configuration = s3control_client.get_public_access_block(
                AccountId=account_id
            )["PublicAccessBlockConfiguration"]

            config_matches_expected = all(
                configuration.get(config_name)
                == expected_public_access_block_config.get(config_name)
                for config_name in expected_public_access_block_config
            )
            if config_matches_expected:
                return {
                    "Message": "Account public access block configuration successfully set.",
                    "Valid": True,
                    "PublicAccessConfig": configuration,
                }
        return {
            "Message": "Account public access block configuration does not match expected configuration.",
            "Valid": False,
            "PublicAccessConfig": None,
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error validating account-level public access block for {account_id}: {str(e)}"
        )


def validate_bucket_public_access_block(
    bucket_name: str,
    expected_public_access_block_config,
) -> ValidateBucketPublicAccessBlockResponse:
    s3_client = connect_to_service("s3")
    try:
        configuration: PublicAccessConfiguration = s3_client.get_public_access_block(
            Bucket=bucket_name
        )["PublicAccessBlockConfiguration"]

        for configuration_name, actual_configuration in configuration.items():
            if (
                actual_configuration
                != expected_public_access_block_config[configuration_name]
            ):
                return {
                    "Message": "Bucket public access block configuration does not match expected configuration.",
                    "Valid": False,
                    "PublicAccessConfig": configuration,
                }

        return {
            "Message": "Bucket public access block configuration successfully set.",
            "Valid": True,
            "PublicAccessConfig": configuration,
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error validating s3 bucket {bucket_name} public access block: {str(e)}"
        )
