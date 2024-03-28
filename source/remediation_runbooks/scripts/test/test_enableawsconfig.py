# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
import botocore.session
import EnableAWSConfig_createconfigbucket as createconfigbucket
import EnableAWSConfig_createtopic as createtopic
import EnableAWSConfig_enableconfig as enableconfig
import EnableAWSConfig_summary as summary
from botocore.config import Config
from botocore.stub import ANY, Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name


def test_create_config_bucket(mocker):
    event = {
        "kms_key_arn": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "partition": "aws",
        "account": "111111111111",
        "region": "us-west-2",
        "logging_bucket": "mahfakebukkit",
    }
    bucket = f'so0111-aws-config-{event["region"]}-{event["account"]}'

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSConfigBucketPermissionsCheck",
                "Effect": "Allow",
                "Principal": {"Service": ["config.amazonaws.com"]},
                "Action": "s3:GetBucketAcl",
                "Resource": f'arn:{event["partition"]}:s3:::{bucket}',
            },
            {
                "Sid": "AWSConfigBucketExistenceCheck",
                "Effect": "Allow",
                "Principal": {"Service": ["config.amazonaws.com"]},
                "Action": "s3:ListBucket",
                "Resource": f'arn:{event["partition"]}:s3:::{bucket}',
            },
            {
                "Sid": "AWSConfigBucketDelivery",
                "Effect": "Allow",
                "Principal": {"Service": ["config.amazonaws.com"]},
                "Action": "s3:PutObject",
                "Resource": f'arn:{event["partition"]}:s3:::{bucket}/*',
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
        ],
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)
    s3_stubber = Stubber(s3)

    s3_stubber.add_response(
        "create_bucket",
        {},
        {
            "ACL": "private",
            "Bucket": bucket,
            "CreateBucketConfiguration": {"LocationConstraint": event["region"]},
        },
    )

    s3_stubber.add_response(
        "put_bucket_encryption",
        {},
        {
            "Bucket": bucket,
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "1234abcd-12ab-34cd-56ef-1234567890ab",
                        }
                    }
                ]
            },
        },
    )

    s3_stubber.add_response(
        "put_public_access_block",
        {},
        {
            "Bucket": bucket,
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        },
    )

    s3_stubber.add_response(
        "put_bucket_logging",
        {},
        {
            "Bucket": bucket,
            "BucketLoggingStatus": {
                "LoggingEnabled": {
                    "TargetBucket": event["logging_bucket"],
                    "TargetPrefix": f"access-logs/{bucket}",
                }
            },
        },
    )

    s3_stubber.add_response(
        "put_bucket_policy", {}, {"Bucket": bucket, "Policy": json.dumps(bucket_policy)}
    )

    s3_stubber.activate()
    mocker.patch("EnableAWSConfig_createconfigbucket.connect_to_s3", return_value=s3)
    createconfigbucket.create_encrypted_bucket(event, {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()


def test_bucket_already_exists(mocker):
    event = {
        "kms_key_arn": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "partition": "aws",
        "account": "111111111111",
        "region": "us-west-2",
        "logging_bucket": "mahfakebukkit",
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)

    s3_stubber.add_client_error("create_bucket", "BucketAlreadyExists")

    s3_stubber.activate()
    mocker.patch("EnableAWSConfig_createconfigbucket.connect_to_s3", return_value=s3)
    createconfigbucket.create_encrypted_bucket(event, {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()


def test_create_topic(mocker):
    event = {
        "kms_key_arn": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "topic_name": "sharr-test",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    sns = botocore.session.get_session().create_client("sns", config=BOTO_CONFIG)
    mocker.patch("EnableAWSConfig_createtopic.connect_to_sns", return_value=sns)
    sns_stubber = Stubber(sns)

    ssm = botocore.session.get_session().create_client("ssm", config=BOTO_CONFIG)
    mocker.patch("EnableAWSConfig_createtopic.connect_to_ssm", return_value=ssm)
    ssm_stubber = Stubber(ssm)

    sns_stubber.add_response(
        "create_topic",
        {"TopicArn": "arn:aws:sns:us-west-2:111111111111:sharr-test"},
        {
            "Name": event["topic_name"],
            "Attributes": {"KmsMasterKeyId": event["kms_key_arn"].split("key/")[1]},
        },
    )

    ssm_stubber.add_response(
        "put_parameter",
        {},
        {
            "Name": "/Solutions/SO0111/SNS_Topic_Config.1",
            "Description": "SNS Topic for AWS Config updates",
            "Type": "String",
            "Overwrite": True,
            "Value": "arn:aws:sns:us-west-2:111111111111:sharr-test",
        },
    )

    sns_stubber.add_response(
        "set_topic_attributes",
        {},
        {
            "TopicArn": "arn:aws:sns:us-west-2:111111111111:sharr-test",
            "AttributeName": "Policy",
            "AttributeValue": ANY,
        },
    )

    sns_stubber.activate()
    ssm_stubber.activate()

    createtopic.create_encrypted_topic(event, {})

    sns_stubber.assert_no_pending_responses()
    ssm_stubber.assert_no_pending_responses()
    sns_stubber.deactivate()
    ssm_stubber.deactivate()


def test_create_topic_already_exists(mocker):
    event = {
        "kms_key_arn": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "topic_name": "sharr-test",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    sns = botocore.session.get_session().create_client("sns", config=BOTO_CONFIG)
    mocker.patch("EnableAWSConfig_createtopic.connect_to_sns", return_value=sns)
    sns_stubber = Stubber(sns)

    sns_stubber.add_client_error("create_topic", "InvalidParameter")

    sns_stubber.add_response(
        "create_topic",
        {"TopicArn": "arn:aws:sns:us-west-2:111111111111:sharr-test"},
        {"Name": event["topic_name"]},
    )

    sns_stubber.add_response(
        "set_topic_attributes",
        {},
        {
            "TopicArn": "arn:aws:sns:us-west-2:111111111111:sharr-test",
            "AttributeName": "Policy",
            "AttributeValue": ANY,
        },
    )

    sns_stubber.activate()

    createtopic.create_encrypted_topic(event, {})

    sns_stubber.assert_no_pending_responses()
    sns_stubber.deactivate()


def test_enable_config(mocker):
    event = {
        "partition": "aws",
        "account": "111111111111",
        "config_bucket": "mahfakebukkit",
        "topic_arn": "arn:aws:sns:us-west-2:111111111111:sharr-test",
        "aws_service_role": "foobarbaz",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    cfg = botocore.session.get_session().create_client("config", config=BOTO_CONFIG)
    mocker.patch("EnableAWSConfig_enableconfig.connect_to_config", return_value=cfg)
    cfg_stubber = Stubber(cfg)

    cfg_stubber.add_response(
        "put_configuration_recorder",
        {},
        {
            "ConfigurationRecorder": {
                "name": "default",
                "roleARN": f'arn:aws:iam::{event["account"]}:role/{event["aws_service_role"]}',
                "recordingGroup": {
                    "allSupported": True,
                    "includeGlobalResourceTypes": True,
                },
            }
        },
    )

    cfg_stubber.add_response(
        "put_delivery_channel",
        {},
        {
            "DeliveryChannel": {
                "name": "default",
                "s3BucketName": event["config_bucket"],
                "s3KeyPrefix": event["account"],
                "snsTopicARN": event["topic_arn"],
                "configSnapshotDeliveryProperties": {
                    "deliveryFrequency": "Twelve_Hours"
                },
            }
        },
    )

    cfg_stubber.add_response(
        "start_configuration_recorder", {}, {"ConfigurationRecorderName": "default"}
    )

    cfg_stubber.activate()

    enableconfig.enable_config(event, {})

    cfg_stubber.assert_no_pending_responses()
    cfg_stubber.deactivate()


def test_enable_config_already_enabled(mocker):
    event = {
        "partition": "aws",
        "account": "111111111111",
        "config_bucket": "mahfakebukkit",
        "topic_arn": "arn:aws:sns:us-west-2:111111111111:sharr-test",
        "aws_service_role": "foobarbaz",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    cfg = botocore.session.get_session().create_client("config", config=BOTO_CONFIG)
    mocker.patch("EnableAWSConfig_enableconfig.connect_to_config", return_value=cfg)
    cfg_stubber = Stubber(cfg)

    cfg_stubber.add_client_error(
        "put_configuration_recorder",
        "MaxNumberOfConfigurationRecordersExceededException",
    )

    cfg_stubber.add_client_error(
        "put_delivery_channel", "MaxNumberOfDeliveryChannelsExceededException"
    )

    cfg_stubber.add_response(
        "start_configuration_recorder", {}, {"ConfigurationRecorderName": "default"}
    )

    cfg_stubber.activate()

    enableconfig.enable_config(event, {})

    cfg_stubber.assert_no_pending_responses()
    cfg_stubber.deactivate()


def test_summary():
    event = {
        "config_bucket": "mahfakebukkit",
        "logging_bucket": "loggingbukkit",
        "sns_topic_arn": "arn:aws:sns:us-west-2:111111111111:sharr-test",
    }

    assert summary.process_results(event, {}) == {
        "response": {"message": "AWS Config successfully enabled", "status": "Success"}
    }
