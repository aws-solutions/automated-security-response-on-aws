# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def connect_to_s3(boto_config):
    return boto3.client("s3", config=boto_config)


def create_encrypted_bucket(event, _):
    boto_config = Config(retries={"mode": "standard"})
    s3 = connect_to_s3(boto_config)

    kms_key_arn = event["kms_key_arn"]
    aws_account = event["account"]
    aws_region = event["region"]
    logging_bucket = event["logging_bucket"]
    bucket_name = "so0111-aws-cloudtrail-" + aws_account

    if create_s3_bucket(s3, bucket_name, aws_region) == "bucket_exists":
        return {"cloudtrail_bucket": bucket_name}
    put_bucket_encryption(s3, bucket_name, kms_key_arn)
    put_public_access_block(s3, bucket_name)
    put_bucket_logging(s3, bucket_name, logging_bucket)

    return {"cloudtrail_bucket": bucket_name}


def create_s3_bucket(s3, bucket_name, aws_region):
    try:
        kwargs = {"Bucket": bucket_name, "ACL": "private"}
        if aws_region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": aws_region}

        s3.create_bucket(**kwargs)

    except ClientError as client_ex:
        exception_type = client_ex.response["Error"]["Code"]
        if exception_type == "BucketAlreadyOwnedByYou":
            print("Bucket " + bucket_name + " already exists and is owned by you")
            return "bucket_exists"
        else:
            exit("Error creating bucket " + bucket_name + " " + str(client_ex))
    except Exception as e:
        exit("Error creating bucket " + bucket_name + " " + str(e))


def put_bucket_encryption(s3, bucket_name, kms_key_arn):
    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": kms_key_arn.split("key/")[1],
                        }
                    }
                ]
            },
        )
    except Exception as e:
        print(e)
        exit(
            "Error applying encryption to bucket "
            + bucket_name
            + " with key "
            + kms_key_arn
        )


def put_public_access_block(s3, bucket_name):
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
        exit(f"Error setting public access block for bucket {bucket_name}: {str(e)}")


def put_bucket_logging(s3, bucket_name, logging_bucket):
    try:
        s3.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": logging_bucket,
                    "TargetPrefix": "cloudtrail-access-logs",
                }
            },
        )
    except Exception as e:
        print(e)
        exit("Error setting public access block for bucket " + bucket_name)
