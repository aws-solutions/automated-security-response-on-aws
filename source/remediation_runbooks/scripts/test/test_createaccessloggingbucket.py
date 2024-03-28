# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TYPE_CHECKING, Any, Dict

import boto3
import botocore.session
import CreateAccessLoggingBucket_createloggingbucket as script
from aws_lambda_powertools.utilities.typing import LambdaContext
from botocore.config import Config
from botocore.stub import Stubber
from CreateAccessLoggingBucket_createloggingbucket import Event
from moto import mock_aws
from pytest import raises

if TYPE_CHECKING:
    from mypy_boto3_s3.type_defs import GetBucketEncryptionOutputTypeDef
else:
    GetBucketEncryptionOutputTypeDef = object


def is_sse_s3_encrypted(config: GetBucketEncryptionOutputTypeDef) -> bool:
    rules = config["ServerSideEncryptionConfiguration"]["Rules"]
    for rule in rules:
        algorithm = rule.get("ApplyServerSideEncryptionByDefault", {}).get(
            "SSEAlgorithm"
        )
        if algorithm == "aws:kms":
            return False
        elif algorithm == "AES256":
            return True
    return False


def test_bucket_created_with_encryption() -> None:
    bucket_name = "my-bucket"
    event: Event = {"BucketName": bucket_name, "AWS_REGION": "us-east-1"}

    with mock_aws():
        script.create_logging_bucket(event, LambdaContext())

        s3 = boto3.client("s3")
        bucket_encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        assert is_sse_s3_encrypted(bucket_encryption)


def get_region() -> str:
    my_session = boto3.session.Session()
    return my_session.region_name


def test_create_logging_bucket(mocker):
    event: Event = {
        "BucketName": "mahbukkit",
        "AWS_REGION": get_region(),
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)
    kwargs: Dict[str, Any] = {
        "Bucket": event["BucketName"],
        "GrantWrite": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        "GrantReadACP": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        "ObjectOwnership": "ObjectWriter",
    }
    if event["AWS_REGION"] != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {
            "LocationConstraint": event["AWS_REGION"]
        }
    s3_stubber.add_response("create_bucket", {}, kwargs)
    s3_stubber.add_response(
        "put_bucket_encryption",
        {},
        {
            "Bucket": event["BucketName"],
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        },
    )
    s3_stubber.activate()
    mocker.patch(
        "CreateAccessLoggingBucket_createloggingbucket.connect_to_s3", return_value=s3
    )
    script.create_logging_bucket(event, LambdaContext())
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()


def test_bucket_already_exists(mocker):
    event: Event = {
        "BucketName": "mahbukkit",
        "AWS_REGION": get_region(),
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)

    s3_stubber.add_client_error("create_bucket", "BucketAlreadyExists")

    s3_stubber.activate()
    mocker.patch(
        "CreateAccessLoggingBucket_createloggingbucket.connect_to_s3", return_value=s3
    )
    with raises(SystemExit):
        script.create_logging_bucket(event, LambdaContext())
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()


def test_bucket_already_owned_by_you(mocker):
    event: Event = {
        "BucketName": "mahbukkit",
        "AWS_REGION": get_region(),
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)

    s3_stubber.add_client_error("create_bucket", "BucketAlreadyOwnedByYou")

    s3_stubber.activate()
    mocker.patch(
        "CreateAccessLoggingBucket_createloggingbucket.connect_to_s3", return_value=s3
    )
    script.create_logging_bucket(event, LambdaContext())
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
