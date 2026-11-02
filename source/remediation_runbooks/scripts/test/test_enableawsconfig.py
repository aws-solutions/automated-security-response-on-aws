# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from unittest import mock

import boto3
import pytest
from botocore.config import Config
from moto import mock_aws

import EnableAWSConfig_createconfigbucket as createconfigbucket
import EnableAWSConfig_createtopic as createtopic
import EnableAWSConfig_enableconfig as enableconfig

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup_key_and_logging_bucket():
    s3_client = boto3.client("s3", config=BOTO_CONFIG)
    s3_client.create_bucket(
        Bucket="my-logging-bucket",
    )
    s3_client.put_bucket_acl(
        Bucket="my-logging-bucket",
        ACL="log-delivery-write",
    )

    kms_client = boto3.client("kms", config=BOTO_CONFIG)
    response = kms_client.create_key()
    return response["KeyMetadata"]["Arn"]


def setup_recorder(recorder_name):
    config_service_role_arn = "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

    config_client = boto3.client("config", config=BOTO_CONFIG)
    config_client.put_configuration_recorder(
        ConfigurationRecorder={
            "name": recorder_name,
            "roleARN": config_service_role_arn,
            "recordingGroup": {
                "allSupported": True,
                "includeGlobalResourceTypes": False,
            },
        }
    )


def setup_delivery_channel():
    config_client = boto3.client("config", config=BOTO_CONFIG)
    config_client.put_delivery_channel(
        DeliveryChannel={
            "name": "default",
            "s3BucketName": "my-config-bucket",
            "s3KeyPrefix": "123456789012",
            "snsTopicARN": "arn:aws:sns:us-east-1:123456789012:sharr-test",
            "configSnapshotDeliveryProperties": {"deliveryFrequency": "Twelve_Hours"},
        }
    )


def start_recording(recorder_name):
    config_client = boto3.client("config", config=BOTO_CONFIG)
    config_client.start_configuration_recorder(ConfigurationRecorderName=recorder_name)


def verify_config_enabled_with_all_resources(recorder_name):
    config_client = boto3.client("config", config=BOTO_CONFIG)
    recorder_status_response = config_client.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[
            recorder_name,
        ]
    )
    assert recorder_status_response["ConfigurationRecordersStatus"][0]["recording"]

    recorders_response = config_client.describe_configuration_recorders(
        ConfigurationRecorderNames=[
            recorder_name,
        ]
    )
    assert recorders_response["ConfigurationRecorders"][0]["recordingGroup"][
        "allSupported"
    ]
    assert recorders_response["ConfigurationRecorders"][0]["recordingGroup"][
        "includeGlobalResourceTypes"
    ]
    assert not recorders_response["ConfigurationRecorders"][0]["recordingGroup"][
        "exclusionByResourceTypes"
    ]["resourceTypes"]


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_enable_config():
    kms_key_arn = setup_key_and_logging_bucket()

    create_topic_event = {"kms_key_arn": kms_key_arn, "topic_name": "sharr-test"}
    create_bucket_event = {
        "kms_key_arn": kms_key_arn,
        "partition": "aws",
        "account": "123456789012",
        "region": "us-east-1",
        "logging_bucket": "my-logging-bucket",
    }
    enable_config_event = {
        "partition": "aws",
        "account": "123456789012",
        "config_bucket": "so0111-aws-config-us-east-1-123456789012",
        "topic_arn": "arn:aws:sns:us-east-1:123456789012:sharr-test",
        "aws_service_role": "aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
    }

    createconfigbucket.create_encrypted_bucket(create_bucket_event, {})
    createtopic.create_encrypted_topic(create_topic_event, {})
    response = enableconfig.enable_config(enable_config_event, {})

    verify_config_enabled_with_all_resources("default")
    assert response["Message"]


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_enable_config_already_enabled():
    kms_key_arn = setup_key_and_logging_bucket()

    create_topic_event = {"kms_key_arn": kms_key_arn, "topic_name": "sharr-test"}
    create_bucket_event = {
        "kms_key_arn": kms_key_arn,
        "partition": "aws",
        "account": "123456789012",
        "region": "us-east-1",
        "logging_bucket": "my-logging-bucket",
    }
    enable_config_event = {
        "partition": "aws",
        "account": "123456789012",
        "config_bucket": "so0111-aws-config-us-east-1-123456789012",
        "topic_arn": "arn:aws:sns:us-east-1:123456789012:sharr-test",
        "aws_service_role": "aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
    }

    createconfigbucket.create_encrypted_bucket(create_bucket_event, {})
    createtopic.create_encrypted_topic(create_topic_event, {})

    # setup existing recorder & channel
    setup_recorder("my-recorder")
    setup_delivery_channel()
    start_recording("my-recorder")

    response = enableconfig.enable_config(enable_config_event, {})

    verify_config_enabled_with_all_resources("my-recorder")
    assert response["Message"]


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_enable_config_with_existing_recorder():
    kms_key_arn = setup_key_and_logging_bucket()

    create_topic_event = {"kms_key_arn": kms_key_arn, "topic_name": "sharr-test"}
    create_bucket_event = {
        "kms_key_arn": kms_key_arn,
        "partition": "aws",
        "account": "123456789012",
        "region": "us-east-1",
        "logging_bucket": "my-logging-bucket",
    }
    enable_config_event = {
        "partition": "aws",
        "account": "123456789012",
        "config_bucket": "so0111-aws-config-us-east-1-123456789012",
        "topic_arn": "arn:aws:sns:us-east-1:123456789012:sharr-test",
        "aws_service_role": "aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
    }

    createconfigbucket.create_encrypted_bucket(create_bucket_event, {})
    createtopic.create_encrypted_topic(create_topic_event, {})

    # setup existing recorder, do not start recording
    setup_recorder("my-recorder")

    response = enableconfig.enable_config(enable_config_event, {})

    verify_config_enabled_with_all_resources("my-recorder")
    assert response["Message"]


@mock_aws
def test_create_config_bucket_returns_arn():
    """Test that create_encrypted_bucket returns the bucket ARN"""
    kms_key_arn = setup_key_and_logging_bucket()

    event = {
        "kms_key_arn": kms_key_arn,
        "partition": "aws",
        "account": "123456789012",
        "region": "us-east-1",
        "logging_bucket": "my-logging-bucket",
    }

    result = createconfigbucket.create_encrypted_bucket(event, {})

    assert "config_bucket" in result
    assert "ResourceArn" in result
    assert result["config_bucket"] == "so0111-aws-config-us-east-1-123456789012"
    assert (
        result["ResourceArn"] == "arn:aws:s3:::so0111-aws-config-us-east-1-123456789012"
    )


@mock_aws
def test_create_config_bucket_returns_arn_for_existing_bucket():
    """Test that create_encrypted_bucket returns ARN even when bucket already exists"""
    kms_key_arn = setup_key_and_logging_bucket()

    event = {
        "kms_key_arn": kms_key_arn,
        "partition": "aws",
        "account": "123456789012",
        "region": "us-east-1",
        "logging_bucket": "my-logging-bucket",
    }

    # Create bucket first time
    result1 = createconfigbucket.create_encrypted_bucket(event, {})
    assert "ResourceArn" in result1

    # Create bucket second time (should return "already exists")
    result2 = createconfigbucket.create_encrypted_bucket(event, {})
    assert "ResourceArn" in result2
    assert (
        result2["ResourceArn"]
        == "arn:aws:s3:::so0111-aws-config-us-east-1-123456789012"
    )


@mock_aws
def test_create_config_bucket_fails_when_another_account_owns_the_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bucket name owned by another account must not be used as the Config bucket."""
    bucket_name = "so0111-aws-config-us-east-1-111111111111"
    monkeypatch.setenv("MOTO_ACCOUNT_ID", "999999999999")
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=bucket_name)
    monkeypatch.setenv("MOTO_ACCOUNT_ID", "111111111111")

    event = {
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/unused",
        "partition": "aws",
        "account": "111111111111",
        "region": "us-east-1",
        "logging_bucket": "my-logging-bucket",
    }

    with pytest.raises(SystemExit, match="already owned by another AWS account"):
        createconfigbucket.create_encrypted_bucket(event, {})


def test_create_config_bucket_fails_closed_on_an_unexpected_s3_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any CreateBucket error other than BucketAlreadyOwnedByYou must stop, not adopt the bucket."""
    from botocore.exceptions import ClientError

    def raise_access_denied(*_args, **_kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "CreateBucket"
        )

    fake_s3 = mock.Mock()
    fake_s3.create_bucket.side_effect = raise_access_denied
    monkeypatch.setattr(createconfigbucket, "connect_to_s3", lambda _config: fake_s3)

    event = {
        "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/unused",
        "partition": "aws",
        "account": "123456789012",
        "region": "us-east-1",
        "logging_bucket": "my-logging-bucket",
    }

    with pytest.raises(SystemExit, match="AccessDenied"):
        createconfigbucket.create_encrypted_bucket(event, {})


@mock_aws
def test_create_config_bucket_reuses_bucket_owned_by_this_account_outside_us_east_1() -> (
    None
):
    """Outside us-east-1, S3 reports BucketAlreadyOwnedByYou for a bucket this account owns; reuse it."""
    region = "eu-west-1"
    bucket_name = f"so0111-aws-config-{region}-123456789012"
    boto3.client("s3", region_name=region).create_bucket(
        Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
    )

    event = {
        "kms_key_arn": "arn:aws:kms:eu-west-1:123456789012:key/unused",
        "partition": "aws",
        "account": "123456789012",
        "region": region,
        "logging_bucket": "my-logging-bucket",
    }

    result = createconfigbucket.create_encrypted_bucket(event, {})

    assert result["config_bucket"] == bucket_name
