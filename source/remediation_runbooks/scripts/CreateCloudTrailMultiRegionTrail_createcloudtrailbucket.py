# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TYPE_CHECKING, TypedDict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.typing import LambdaContext
    from mypy_boto3_s3.client import S3Client
else:
    S3Client = object
    LambdaContext = object


class Event(TypedDict):
    kms_key_arn: str
    account: str
    region: str
    logging_bucket: str


class Output(TypedDict):
    cloudtrail_bucket: str
    ResourceArn: str


def connect_to_s3(boto_config: Config) -> S3Client:
    return boto3.client("s3", config=boto_config)


def create_encrypted_bucket(event: Event, _: LambdaContext) -> Output:
    boto_config = Config(retries={"mode": "standard"})
    s3 = connect_to_s3(boto_config)

    kms_key_arn: str = event["kms_key_arn"]
    aws_account: str = event["account"]
    aws_region: str = event["region"]
    logging_bucket: str = event["logging_bucket"]
    bucket_name = "so0111-aws-cloudtrail-" + aws_account

    partition = "aws"
    if "cn-" in aws_region:
        partition = "aws-cn"
    elif "us-gov" in aws_region:
        partition = "aws-us-gov"
    resource_arn = f"arn:{partition}:s3:::{bucket_name}"

    if create_s3_bucket(s3, bucket_name, aws_region) == "bucket_exists":
        return {"cloudtrail_bucket": bucket_name, "ResourceArn": resource_arn}
    put_bucket_encryption(s3, bucket_name, kms_key_arn)
    put_public_access_block(s3, bucket_name)
    put_bucket_logging(s3, bucket_name, logging_bucket)

    return {"cloudtrail_bucket": bucket_name, "ResourceArn": resource_arn}


def create_s3_bucket(s3: S3Client, bucket_name: str, aws_region: str) -> str:
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


def put_bucket_encryption(s3: S3Client, bucket_name: str, kms_key_arn: str) -> None:
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


def put_public_access_block(s3: S3Client, bucket_name: str) -> None:
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


def put_bucket_logging(s3: S3Client, bucket_name: str, logging_bucket: str) -> None:
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
