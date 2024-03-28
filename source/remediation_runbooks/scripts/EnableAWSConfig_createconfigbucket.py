# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

boto_config = Config(retries={"mode": "standard"})


def connect_to_s3(boto_config):
    return boto3.client("s3", config=boto_config)


def create_bucket(bucket_name, aws_region):
    s3 = connect_to_s3(boto_config)
    try:
        if aws_region == "us-east-1":
            s3.create_bucket(ACL="private", Bucket=bucket_name)
        else:
            s3.create_bucket(
                ACL="private",
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": aws_region},
            )
        return "created"

    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # bucket already exists - return
        if exception_type in ["BucketAlreadyExists", "BucketAlreadyOwnedByYou"]:
            print("Bucket " + bucket_name + " already exists")
            return "already exists"
        else:
            exit(f"ERROR creating bucket {bucket_name}: {str(ex)}")
    except Exception as e:
        exit(f"ERROR creating bucket {bucket_name}: {str(e)}")


def encrypt_bucket(bucket_name, kms_key):
    s3 = connect_to_s3(boto_config)
    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_key,
                        }
                    }
                ]
            },
        )
    except Exception as e:
        exit(f"ERROR putting bucket encryption for {bucket_name}: {str(e)}")


def block_public_access(bucket_name):
    s3 = connect_to_s3(boto_config)
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
    except Exception as e:
        exit(f"ERROR setting public access block for bucket {bucket_name}: {str(e)}")


def enable_access_logging(bucket_name, logging_bucket):
    s3 = connect_to_s3(boto_config)
    try:
        s3.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": logging_bucket,
                    "TargetPrefix": f"access-logs/{bucket_name}",
                }
            },
        )
    except Exception as e:
        exit(f"Error setting access logging for bucket {bucket_name}: {str(e)}")


def create_bucket_policy(config_bucket, aws_partition):
    s3 = connect_to_s3(boto_config)
    try:
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSConfigBucketPermissionsCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": ["config.amazonaws.com"]},  # NOSONAR
                    "Action": "s3:GetBucketAcl",
                    "Resource": "arn:" + aws_partition + ":s3:::" + config_bucket,
                },
                {
                    "Sid": "AWSConfigBucketExistenceCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": ["config.amazonaws.com"]},
                    "Action": "s3:ListBucket",
                    "Resource": "arn:" + aws_partition + ":s3:::" + config_bucket,
                },
                {
                    "Sid": "AWSConfigBucketDelivery",
                    "Effect": "Allow",
                    "Principal": {"Service": ["config.amazonaws.com"]},
                    "Action": "s3:PutObject",
                    "Resource": "arn:"
                    + aws_partition
                    + ":s3:::"
                    + config_bucket
                    + "/*",
                    "Condition": {
                        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                    },
                },
            ],
        }
        s3.put_bucket_policy(Bucket=config_bucket, Policy=json.dumps(bucket_policy))
    except Exception as e:
        exit(f"ERROR: PutBucketPolicy failed for {config_bucket}: {str(e)}")


def create_encrypted_bucket(event, _):
    kms_key_arn = event["kms_key_arn"]
    aws_partition = event["partition"]
    aws_account = event["account"]
    aws_region = event["region"]
    logging_bucket = event["logging_bucket"]
    bucket_name = "so0111-aws-config-" + aws_region + "-" + aws_account

    if create_bucket(bucket_name, aws_region) == "already exists":
        return {"config_bucket": bucket_name}

    encrypt_bucket(bucket_name, kms_key_arn.split("key/")[1])
    block_public_access(bucket_name)
    enable_access_logging(bucket_name, logging_bucket)
    create_bucket_policy(bucket_name, aws_partition)

    return {"config_bucket": bucket_name}
