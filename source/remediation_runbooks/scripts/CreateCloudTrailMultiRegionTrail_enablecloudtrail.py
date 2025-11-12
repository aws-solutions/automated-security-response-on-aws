# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def connect_to_cloudtrail(boto_config):
    return boto3.client("cloudtrail", config=boto_config)


def enable_cloudtrail(event, _):
    boto_config = Config(retries={"mode": "standard"})
    ct = connect_to_cloudtrail(boto_config)

    trail_name = "multi-region-cloud-trail"

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
        return {"output": {"Message": message}}

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
                return {"output": {"Message": f"CloudTrail Trail {trail_name} updated"}}
            except Exception as update_error:
                exit(f"Error updating CloudTrail trail: {str(update_error)}")
        else:
            exit(f"Error enabling CloudTrail: {str(e)}")
    except Exception as e:
        exit(f"Error enabling CloudTrail: {str(e)}")
