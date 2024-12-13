# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import logging
import os
import traceback
from typing import Any, List, TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})
logger = logging.getLogger()
logger.setLevel("INFO")


class Response(TypedDict):
    FailedResources: List[str]


def connect_to_service(service: str) -> Any:
    return boto3.client(service, config=boto_config)


def lambda_handler(_: Any, __: Any) -> Response:
    bucket_name = os.environ["BucketName"]
    key_id = os.environ["KMSKeyId"]
    secret_id = os.environ["SecretId"]
    queue_url = os.environ["QueueURL"]

    failed_resources = []
    # Reset remediation resources
    if disable_server_access_logging(bucket_name) != "Success":
        failed_resources.append(bucket_name)
    if disable_kms_key_rotation(key_id) != "Success":
        failed_resources.append(key_id)
    if disable_automatic_secret_rotation(secret_id) != "Success":
        failed_resources.append(secret_id)
    if remove_sqs_queue_encryption(queue_url) != "Success":
        failed_resources.append(queue_url)
    return {"FailedResources": failed_resources}


def disable_server_access_logging(bucket_name: str) -> str:
    s3_client = connect_to_service("s3")
    try:
        s3_client.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus={})
        logger.info(f"Disabled server access logging for bucket {bucket_name}")
        return "Success"
    except Exception as e:
        logger.error(
            f"Encountered an error when disabling server access logging for bucket {bucket_name}: {str(e)}"
        )
        logger.debug(traceback.format_exc())
        return "Failed"


def disable_kms_key_rotation(key_id: str) -> str:
    kms_client = connect_to_service("kms")

    try:
        kms_client.disable_key_rotation(KeyId=key_id)
        logger.info(f"Disabled automatic rotation for key {key_id}")
        return "Success"
    except kms_client.exceptions.DisabledException:
        logger.info(f"KMS Key {key_id} already has rotation disabled.")
        return "Failed"
    except Exception as e:
        logger.error(
            f"Encountered an error when disabling KMS key rotation for key {key_id}: {str(e)}"
        )
        logger.debug(traceback.format_exc())
        return "Failed"


def disable_automatic_secret_rotation(secret_id: str) -> str:
    secrets_manager_client = connect_to_service("secretsmanager")
    try:
        secrets_manager_client.cancel_rotate_secret(SecretId=secret_id)
        logger.info(f"Disabled automatic secret rotation for {secret_id}")
        return "Success"
    except Exception as e:
        logger.error(
            f"Encountered an error when disabling secret rotation for secret {secret_id}: {str(e)}"
        )
        logger.debug(traceback.format_exc())
        return "Failed"


def remove_sqs_queue_encryption(queue_url: str) -> str:
    sqs_client = connect_to_service("sqs")
    try:
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url, Attributes={"KmsMasterKeyId": ""}
        )
        logger.info(f"Removed encryption from Queue {queue_url}")
        return "Success"
    except Exception as e:
        logger.error(
            f"Encountered an error when removing encryption from queue {queue_url}: {str(e)}"
        )
        logger.debug(traceback.format_exc())
        return "Failed"
