# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
import json
import botocore.session
from botocore.stub import Stubber
from botocore.config import Config
import pytest
from pytest_mock import mocker

import CreateAccessLoggingBucket_createloggingbucket as script


def get_region() -> str:
    my_session = boto3.session.Session()
    return my_session.region_name


def test_create_logging_bucket(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "BucketName": "mahbukkit",
        "AWS_REGION": get_region(),
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)
    kwargs = {
        "Bucket": event["BucketName"],
        "GrantWrite": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        "GrantReadACP": "uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
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
    script.create_logging_bucket(event, {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()


def test_bucket_already_exists(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
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
    with pytest.raises(SystemExit):
        script.create_logging_bucket(event, {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()


def test_bucket_already_owned_by_you(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
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
    script.create_logging_bucket(event, {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()
