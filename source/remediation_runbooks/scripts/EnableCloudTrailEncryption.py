# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config


def connect_to_cloudtrail(region, boto_config):
    return boto3.client("cloudtrail", region_name=region, config=boto_config)


def enable_trail_encryption(event, _):
    """
    remediates CloudTrail.2 by enabling SSE-KMS
    On success returns a string map
    On failure returns NoneType
    """
    boto_config = Config(retries={"mode": "standard"})

    if event["trail_region"] != event["exec_region"]:
        exit("ERROR: cross-region remediation is not yet supported")

    ctrail_client = connect_to_cloudtrail(event["trail_region"], boto_config)
    kms_key_arn = event["kms_key_arn"]

    try:
        ctrail_client.update_trail(Name=event["trail"], KmsKeyId=kms_key_arn)
        return {
            "response": {
                "message": f'Enabled KMS CMK encryption on {event["trail"]}',
                "status": "Success",
            }
        }
    except Exception as e:
        exit(f"Error enabling SSE-KMS encryption: {str(e)}")
