# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TYPE_CHECKING, TypedDict, cast

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


def connect_to_s3(boto_config: Config) -> S3Client:
    s3: S3Client = boto3.client("s3", config=boto_config)
    return s3


class Event(TypedDict):
    BucketName: str
    AWS_REGION: str


class Output(TypedDict):
    Message: str


class Response(TypedDict):
    output: Output


def create_logging_bucket(event: Event, _: LambdaContext) -> Response:
    boto_config = Config(retries={"mode": "standard"})
    s3 = connect_to_s3(boto_config)

    try:
        kwargs: CreateBucketRequestRequestTypeDef = {
            "Bucket": event["BucketName"],
            "GrantWrite": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
            "GrantReadACP": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
            "ObjectOwnership": "ObjectWriter",
        }
        if event["AWS_REGION"] != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {
                "LocationConstraint": cast(
                    BucketLocationConstraintType, event["AWS_REGION"]
                )
            }

        s3.create_bucket(**kwargs)

        s3.put_bucket_encryption(
            Bucket=event["BucketName"],
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
        return {"output": {"Message": f'Bucket {event["BucketName"]} created'}}
    except ClientError as error:
        if error.response["Error"]["Code"] != "BucketAlreadyOwnedByYou":
            exit(str(error))
        else:
            return {
                "output": {
                    "Message": f'Bucket {event["BucketName"]} already exists and is owned by you'
                }
            }
    except Exception as e:
        print(e)
        exit(str(e))
