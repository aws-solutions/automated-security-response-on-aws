# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import time
from typing import Any, Dict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def create_cloudtrail_bucket_policy(bucket, trail_arn, partition, account):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:{partition}:s3:::{bucket}",
                "Condition": {"StringEquals": {"AWS:SourceArn": trail_arn}},
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:{partition}:s3:::{bucket}/AWSLogs/{account}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "AWS:SourceArn": trail_arn,
                    }
                },
            },
            {
                "Sid": "AllowSSLRequestsOnly",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:{partition}:s3:::{bucket}",
                    f"arn:{partition}:s3:::{bucket}/*",
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }


def merge_bucket_policies(
    existing: Dict[str, Any], new: Dict[str, Any]
) -> Dict[str, Any]:
    if not existing or "Statement" not in existing:
        return new

    merged = existing.copy()
    existing_sids = {stmt.get("Sid") for stmt in merged.get("Statement", [])}

    for stmt in new.get("Statement", []):
        if stmt.get("Sid") not in existing_sids:
            merged["Statement"].append(stmt)
        else:
            for i, existing_stmt in enumerate(merged["Statement"]):
                if existing_stmt.get("Sid") == stmt.get("Sid"):
                    merged["Statement"][i] = stmt
                    break
    return merged


def fix_cloudtrail_bucket_policy_for_logging(event, _):
    boto_config = Config(retries={"mode": "standard", "max_attempts": 5})
    s3 = boto3.client("s3", config=boto_config)
    cloudtrail = boto3.client("cloudtrail", config=boto_config)

    trail_name = event["trail_name"]
    aws_partition = event["partition"]
    aws_account = event["account"]

    try:
        trail_response = cloudtrail.get_trail(Name=trail_name)
        trail = trail_response["Trail"]
        bucket = trail["S3BucketName"]
        trail_arn = trail["TrailARN"]

        if not bucket or not trail_arn:
            raise ValueError(f"Trail {trail_name} missing S3 bucket or ARN")

        existing_policy = None
        try:
            policy_response = s3.get_bucket_policy(Bucket=bucket)
            existing_policy = json.loads(policy_response["Policy"])
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise

        cloudtrail_policy = create_cloudtrail_bucket_policy(
            bucket, trail_arn, aws_partition, aws_account
        )
        final_policy = (
            merge_bucket_policies(existing_policy, cloudtrail_policy)
            if existing_policy
            else cloudtrail_policy
        )

        for attempt in range(3):
            try:
                s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(final_policy))
                break
            except ClientError as e:
                if attempt < 2 and e.response["Error"]["Code"] in [
                    "ServiceUnavailable",
                    "SlowDown",
                ]:
                    time.sleep(2**attempt)
                    continue
                raise

        return {
            "output": {
                "Message": f"Fixed bucket policy for {bucket}",
                "TrailArn": trail_arn,
                "BucketName": bucket,
                "PolicyMerged": existing_policy is not None,
            }
        }

    except Exception as e:
        return {
            "output": {
                "Message": f"Error fixing CloudTrail bucket policy: {str(e)}",
                "Error": str(e),
                "TrailName": trail_name,
            }
        }
