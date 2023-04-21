# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client
    from aws_lambda_powertools.utilities.typing import LambdaContext
else:
    S3Client = object
    LambdaContext = object


def connect_to_s3(boto_config: Config) -> S3Client:
    return boto3.client("s3", config=boto_config)


def create_logging_bucket(event: Dict, _: LambdaContext) -> Dict:
    boto_config = Config(retries={"mode": "standard"})
    s3 = connect_to_s3(boto_config)

    try:
        kwargs = {
            "Bucket": event["BucketName"],
            "GrantWrite": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
            "GrantReadACP": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
            "ObjectOwnership": "ObjectWriter",
        }
        if event["AWS_REGION"] != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {
                "LocationConstraint": event["AWS_REGION"]
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
