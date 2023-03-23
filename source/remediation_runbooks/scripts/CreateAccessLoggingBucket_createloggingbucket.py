# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config


def connect_to_s3(boto_config):
    return boto3.client("s3", config=boto_config)


def create_logging_bucket(event, _):
    boto_config = Config(retries={"mode": "standard"})
    s3 = connect_to_s3(boto_config)

    try:
        kwargs = {
            "Bucket": event["BucketName"],
            "GrantWrite": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
            "GrantReadACP": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
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
