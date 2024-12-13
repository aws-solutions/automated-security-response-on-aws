# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
import EnableAWSConfig_createconfigbucket as createconfigbucket
import EnableAWSConfig_createtopic as createtopic
import EnableAWSConfig_enableconfig as enableconfig
from botocore.config import Config
from moto import mock_aws

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
