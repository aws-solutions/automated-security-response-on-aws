# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
from botocore.config import Config


def connect_to_s3(boto_config):
    return boto3.client("s3", config=boto_config)


def create_bucket_policy(event, _):
    boto_config = Config(retries={"mode": "standard"})
    s3 = connect_to_s3(boto_config)

    cloudtrail_bucket = event["cloudtrail_bucket"]
    aws_partition = event["partition"]
    aws_account = event["account"]
    try:
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck20150319",
                    "Effect": "Allow",
                    "Principal": {"Service": ["cloudtrail.amazonaws.com"]},
                    "Action": "s3:GetBucketAcl",
                    "Resource": "arn:" + aws_partition + ":s3:::" + cloudtrail_bucket,
                },
                {
                    "Sid": "AWSCloudTrailWrite20150319",
                    "Effect": "Allow",
                    "Principal": {"Service": ["cloudtrail.amazonaws.com"]},
                    "Action": "s3:PutObject",
                    "Resource": "arn:"
                    + aws_partition
                    + ":s3:::"
                    + cloudtrail_bucket
                    + "/AWSLogs/"
                    + aws_account
                    + "/*",
                    "Condition": {
                        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"},
                    },
                },
                {
                    "Sid": "AllowSSLRequestsOnly",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        "arn:" + aws_partition + ":s3:::" + cloudtrail_bucket,
                        "arn:" + aws_partition + ":s3:::" + cloudtrail_bucket + "/*",
                    ],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
            ],
        }
        s3.put_bucket_policy(Bucket=cloudtrail_bucket, Policy=json.dumps(bucket_policy))
        return {
            "output": {"Message": f"Set bucket policy for bucket {cloudtrail_bucket}"}
        }
    except Exception as e:
        print(e)
        exit("PutBucketPolicy failed: " + str(e))
