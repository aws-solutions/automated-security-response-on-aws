# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from typing import TYPE_CHECKING, TypedDict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_cloudtrail.client import CloudTrailClient
else:
    CloudTrailClient = object


class Event(TypedDict):
    cloudtrail_bucket: str
    kms_key_arn: str
    account_id: str


class Output(TypedDict):
    Message: str
    ResourceArn: str


def get_partition_from_region(region: str) -> str:
    """Derive AWS partition from region name."""
    if region.startswith("cn-"):
        return "aws-cn"
    elif region.startswith("us-gov"):
        return "aws-us-gov"
    else:
        return "aws"


def connect_to_cloudtrail(boto_config: Config) -> CloudTrailClient:
    return boto3.client("cloudtrail", config=boto_config)


def enable_cloudtrail(event: Event, _) -> dict:
    boto_config = Config(retries={"mode": "standard"})
    ct = connect_to_cloudtrail(boto_config)
    region = os.environ.get("AWS_REGION", "us-east-1")
    partition = get_partition_from_region(region)
    account_id = event["account_id"]

    trail_name = "multi-region-cloud-trail"
    trail_arn = f"arn:{partition}:cloudtrail:{region}:{account_id}:trail/{trail_name}"

    try:
        existing_trails = ct.describe_trails(trailNameList=[trail_name])

        if existing_trails.get("trailList"):
            # Trail exists, update it
            print(f"Trail {trail_name} already exists, updating configuration")
            ct.update_trail(
                Name=trail_name,
                S3BucketName=event["cloudtrail_bucket"],
                IncludeGlobalServiceEvents=True,
                EnableLogFileValidation=True,
                IsMultiRegionTrail=True,
                KmsKeyId=event["kms_key_arn"],
            )
            message = f"CloudTrail Trail {trail_name} updated"
        else:
            # Trail doesn't exist, create it
            ct.create_trail(
                Name=trail_name,
                S3BucketName=event["cloudtrail_bucket"],
                IncludeGlobalServiceEvents=True,
                EnableLogFileValidation=True,
                IsMultiRegionTrail=True,
                KmsKeyId=event["kms_key_arn"],
            )
            message = f"CloudTrail Trail {trail_name} created"

        ct.start_logging(Name=trail_name)
        return {"output": {"Message": message, "ResourceArn": trail_arn}}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "TrailAlreadyExistsException":
            print(f"Trail {trail_name} already exists, updating configuration")
            try:
                ct.update_trail(
                    Name=trail_name,
                    S3BucketName=event["cloudtrail_bucket"],
                    IncludeGlobalServiceEvents=True,
                    EnableLogFileValidation=True,
                    IsMultiRegionTrail=True,
                    KmsKeyId=event["kms_key_arn"],
                )
                ct.start_logging(Name=trail_name)
                return {
                    "output": {
                        "Message": f"CloudTrail Trail {trail_name} updated",
                        "ResourceArn": trail_arn,
                    }
                }
            except Exception as update_error:
                exit(f"Error updating CloudTrail trail: {str(update_error)}")
        else:
            exit(f"Error enabling CloudTrail: {str(e)}")
    except Exception as e:
        exit(f"Error enabling CloudTrail: {str(e)}")
