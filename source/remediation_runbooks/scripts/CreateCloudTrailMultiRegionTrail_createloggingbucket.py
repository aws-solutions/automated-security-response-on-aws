# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TYPE_CHECKING, Dict, Literal, TypedDict, cast

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.typing import LambdaContext
    from mypy_boto3_s3.client import S3Client
    from mypy_boto3_s3.literals import BucketLocationConstraintType
    from mypy_boto3_s3.type_defs import CreateBucketRequestRequestTypeDef
else:
    S3Client = object
    LambdaContext = object
    BucketLocationConstraintType = object
    CreateBucketRequestRequestTypeDef = object


def connect_to_s3() -> S3Client:
    s3: S3Client = boto3.client("s3", config=Config(retries={"mode": "standard"}))
    return s3


class Event(TypedDict):
    account: str
    region: str
    kms_key_arn: str


def create_logging_bucket(
    event: Event, _: LambdaContext
) -> Dict[Literal["logging_bucket"], str]:
    s3 = connect_to_s3()

    kms_key_arn: str = event["kms_key_arn"]
    aws_account: str = event["account"]
    aws_region: str = event["region"]
    bucket_name = "so0111-access-logs-" + aws_region + "-" + aws_account

    if create_bucket(s3, bucket_name, aws_region) == "bucket_exists":
        return {"logging_bucket": bucket_name}
    encrypt_bucket(s3, bucket_name, kms_key_arn)
    put_access_block(s3, bucket_name)
    put_bucket_acl(s3, bucket_name)

    return {"logging_bucket": bucket_name}


def create_bucket(s3: S3Client, bucket_name: str, aws_region: str) -> str:
    try:
        kwargs: CreateBucketRequestRequestTypeDef = {
            "Bucket": bucket_name,
            "ACL": "private",
            "ObjectOwnership": "ObjectWriter",
        }
        if aws_region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {
                "LocationConstraint": cast(BucketLocationConstraintType, aws_region)
            }

        s3.create_bucket(**kwargs)
        return "success"
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # bucket already exists - return
        if exception_type == "BucketAlreadyOwnedByYou":
            print("Bucket " + bucket_name + " already exists and is owned by you")
            return "bucket_exists"
        else:
            print(ex)
            exit("Error creating bucket " + bucket_name)
    except Exception as e:
        print(e)
        exit("Error creating bucket " + bucket_name)


def encrypt_bucket(s3: S3Client, bucket_name: str, kms_key_arn: str) -> None:
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
        exit("Error encrypting bucket " + bucket_name + ": " + str(e))


def put_access_block(s3: S3Client, bucket_name: str) -> None:
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
        exit(
            "Error setting public access block for bucket "
            + bucket_name
            + ": "
            + str(e)
        )


def put_bucket_acl(s3: S3Client, bucket_name: str) -> None:
    try:
        s3.put_bucket_acl(
            Bucket=bucket_name,
            GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
            GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        )
    except Exception as e:
        exit("Error setting ACL for bucket " + bucket_name + ": " + str(e))
