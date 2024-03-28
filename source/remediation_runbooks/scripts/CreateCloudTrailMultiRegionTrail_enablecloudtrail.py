# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config


def connect_to_cloudtrail(boto_config):
    return boto3.client("cloudtrail", config=boto_config)


def enable_cloudtrail(event, _):
    boto_config = Config(retries={"mode": "standard"})
    ct = connect_to_cloudtrail(boto_config)

    try:
        ct.create_trail(
            Name="multi-region-cloud-trail",
            S3BucketName=event["cloudtrail_bucket"],
            IncludeGlobalServiceEvents=True,
            EnableLogFileValidation=True,
            IsMultiRegionTrail=True,
            KmsKeyId=event["kms_key_arn"],
        )
        ct.start_logging(Name="multi-region-cloud-trail")
        return {
            "output": {"Message": "CloudTrail Trail multi-region-cloud-trail created"}
        }
    except Exception as e:
        exit("Error enabling AWS Config: " + str(e))
