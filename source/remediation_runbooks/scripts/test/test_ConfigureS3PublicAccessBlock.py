# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import boto3
import botocore.session
import ConfigureS3PublicAccessBlock as remediation
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
BUCKET_NAME = "my-test-bucket"
MOTO_ACCOUNT_ID = "123456789012"  # default moto account id
TEST_POLICY = {
    "RestrictPublicBuckets": True,
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
}


def setup_bucket():
    s3_client = boto3.client("s3", config=BOTO_CONFIG)
    s3_client.create_bucket(
        Bucket=BUCKET_NAME,
    )
    return BUCKET_NAME


def setup_account():
    s3_client = boto3.client("s3control", config=BOTO_CONFIG)
    s3_client.put_public_access_block(
        PublicAccessBlockConfiguration={
            "RestrictPublicBuckets": False,
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
        },
        AccountId=MOTO_ACCOUNT_ID,
    )


def setup_client_stubber(client, method, mocker):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_client_error(
        method,
        service_error_code="ServiceException",
        service_message="Error",
    )
    mocker.patch("ConfigureS3PublicAccessBlock.connect_to_service", return_value=client)
    return stubber


def set_bucket_public_access_block(bucket, policy):
    s3_client = boto3.client("s3", config=BOTO_CONFIG)
    s3_client.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration=policy,
    )


@mock_aws
def test_handle_s3_bucket():
    bucket = setup_bucket()

    result = remediation.handle_s3_bucket(
        {
            "Bucket": bucket,
            "RestrictPublicBuckets": TEST_POLICY["RestrictPublicBuckets"],
            "BlockPublicAcls": TEST_POLICY["BlockPublicAcls"],
            "IgnorePublicAcls": TEST_POLICY["IgnorePublicAcls"],
            "BlockPublicPolicy": TEST_POLICY["BlockPublicPolicy"],
        },
        None,
    )

    assert result["Status"] == "Success"
    for config_name, config_value in result["PublicAccessConfig"].items():
        assert config_value == TEST_POLICY[config_name]


@mock_aws
def test_handle_s3_bucket_asserts_bucket_ownership(mocker):
    # The bucket-level put must carry ExpectedBucketOwner = the caller account, so
    # a bucket renamed away between finding and remediation cannot have another
    # account's bucket reconfigured. Spy on the real S3 client call.
    bucket = setup_bucket()
    real_client = boto3.client("s3", config=BOTO_CONFIG)
    put_spy = mocker.spy(real_client, "put_public_access_block")
    mocker.patch(
        "ConfigureS3PublicAccessBlock.connect_to_service",
        side_effect=lambda service: (
            real_client
            if service == "s3"
            else boto3.client(service, config=BOTO_CONFIG)
        ),
    )

    result = remediation.handle_s3_bucket(
        {
            "Bucket": bucket,
            "RestrictPublicBuckets": TEST_POLICY["RestrictPublicBuckets"],
            "BlockPublicAcls": TEST_POLICY["BlockPublicAcls"],
            "IgnorePublicAcls": TEST_POLICY["IgnorePublicAcls"],
            "BlockPublicPolicy": TEST_POLICY["BlockPublicPolicy"],
        },
        None,
    )

    assert result["Status"] == "Success"
    assert put_spy.call_args.kwargs["ExpectedBucketOwner"] == MOTO_ACCOUNT_ID


@mock_aws
def test_handle_s3_bucket_with_invalid_bucket_policy(mocker):
    bucket = setup_bucket()
    invalid_bucket_policy = {
        "RestrictPublicBuckets": False,
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
    }
    set_bucket_public_access_block(bucket, invalid_bucket_policy)
    # Mock put_s3_bucket_public_access_block to test that validate_bucket_public_access_block correctly identifies
    # invalid policy
    mocker.patch(
        "ConfigureS3PublicAccessBlock.put_s3_bucket_public_access_block",
        return_value=None,
    )

    result = remediation.handle_s3_bucket(
        {
            "Bucket": bucket,
            "RestrictPublicBuckets": TEST_POLICY["RestrictPublicBuckets"],
            "BlockPublicAcls": TEST_POLICY["BlockPublicAcls"],
            "IgnorePublicAcls": TEST_POLICY["IgnorePublicAcls"],
            "BlockPublicPolicy": TEST_POLICY["BlockPublicPolicy"],
        },
        None,
    )
    assert result["Status"] == "Failed"
    assert result["PublicAccessConfig"] == invalid_bucket_policy


def test_handle_s3_bucket_with_invalid_event():
    with pytest.raises(Exception) as e:
        remediation.handle_s3_bucket({"my-param": "some-value"}, None)

    assert re.match(
        r"Encountered error configuring public access block for S3 Bucket:",
        str(e.value),
    )


@mock_aws
def test_handle_account(mocker):
    mocker.patch("ConfigureS3PublicAccessBlock.sleep", return_value=None)
    setup_account()
    result = remediation.handle_account(
        {
            "AccountId": MOTO_ACCOUNT_ID,
            "RestrictPublicBuckets": TEST_POLICY["RestrictPublicBuckets"],
            "BlockPublicAcls": TEST_POLICY["BlockPublicAcls"],
            "IgnorePublicAcls": TEST_POLICY["IgnorePublicAcls"],
            "BlockPublicPolicy": TEST_POLICY["BlockPublicPolicy"],
        },
        None,
    )
    assert result["Status"] == "Success"


@mock_aws
def test_handle_account_with_invalid_policy(mocker):
    mocker.patch("ConfigureS3PublicAccessBlock.sleep", return_value=None)
    # Mock put_account_public_access_block to test that validate_account_public_access_block correctly identifies
    # invalid policy
    mocker.patch(
        "ConfigureS3PublicAccessBlock.put_account_public_access_block",
        return_value=None,
    )
    setup_account()

    result = remediation.handle_account(
        {
            "AccountId": MOTO_ACCOUNT_ID,
            "RestrictPublicBuckets": TEST_POLICY["RestrictPublicBuckets"],
            "BlockPublicAcls": TEST_POLICY["BlockPublicAcls"],
            "IgnorePublicAcls": TEST_POLICY["IgnorePublicAcls"],
            "BlockPublicPolicy": TEST_POLICY["BlockPublicPolicy"],
        },
        None,
    )

    assert result["Status"] == "Failed"


def test_handle_account_with_invalid_event(mocker):
    mocker.patch("ConfigureS3PublicAccessBlock.sleep", return_value=None)
    with pytest.raises(Exception) as e:
        remediation.handle_account({"my-param": "some-value"}, None)

    assert re.match(
        r"Encountered error configuring public access block for account",
        str(e.value),
    )


def test_put_s3_bucket_public_access_block_error(mocker):
    s3_stubber = setup_client_stubber("s3", "put_public_access_block", mocker)

    s3_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.put_s3_bucket_public_access_block(
            BUCKET_NAME,
            {
                "RestrictPublicBuckets": True,
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
            },
            "111111111111",
        )

    assert re.match(
        r"Encountered error putting public access block on bucket my-test-bucket",
        str(e.value),
    )
    s3_stubber.deactivate()


def test_validate_bucket_public_access_block_error(mocker):
    s3_stubber = setup_client_stubber("s3", "get_public_access_block", mocker)

    s3_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.validate_bucket_public_access_block(
            BUCKET_NAME,
            {
                "RestrictPublicBuckets": True,
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
            },
            "111111111111",
        )

    assert re.match(
        r"Encountered error validating s3 bucket .* public access block:",
        str(e.value),
    )
    s3_stubber.deactivate()


def test_put_account_public_access_block_error(mocker):
    s3control_stubber = setup_client_stubber(
        "s3control", "put_public_access_block", mocker
    )

    s3control_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.put_account_public_access_block(
            MOTO_ACCOUNT_ID,
            {
                "RestrictPublicBuckets": True,
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
            },
        )

    assert re.match(
        r"Encountered error putting public access block on account",
        str(e.value),
    )
    s3control_stubber.deactivate()


def test_validate_account_public_access_block_error(mocker):
    mocker.patch("ConfigureS3PublicAccessBlock.sleep", return_value=None)
    s3control_stubber = setup_client_stubber(
        "s3control", "get_public_access_block", mocker
    )

    s3control_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.validate_account_public_access_block(
            MOTO_ACCOUNT_ID,
            {
                "RestrictPublicBuckets": True,
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
            },
        )

    assert re.match(
        r"Encountered error validating account-level public access block",
        str(e.value),
    )
    s3control_stubber.deactivate()
