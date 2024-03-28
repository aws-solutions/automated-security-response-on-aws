# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `enable_bucket_event_notifications` remediation script"""

import json
from unittest.mock import patch

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import UnknownRegionError
from botocore.stub import Stubber
from enable_bucket_event_notifications import lambda_handler


def partition_from_region(session: boto3.session.Session):
    """
    returns the partition for a given region
    On success returns a string
    On failure returns aws
    """
    try:
        partition = session.get_partition_for_region(session.region_name)
    except UnknownRegionError:
        return "aws"

    return partition


bucket_name = "test-bucket"
topic_name = "testTopic"
account_id = "111111111"
event_types = [
    "s3:ReducedRedundancyLostObject",
    "s3:ObjectCreated:*",
    "s3:ObjectRemoved:*",
    "s3:ObjectRestore:*",
    "s3:Replication:*",
    "s3:LifecycleExpiration:*",
    "s3:LifecycleTransition",
    "s3:IntelligentTiering",
    "s3:ObjectTagging:*",
    "s3:ObjectAcl:Put",
]
region = "us-east-1"
session = boto3.session.Session(region_name="us-east-1")
partition = partition_from_region(session)
topic_arn = f"arn:{partition}:sns:{region}:{account_id}:{topic_name}"
BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

policy = {
    "Version": "2012-10-17",
    "Id": "ASR Notification Policy",
    "Statement": [
        {
            "Sid": bucket_name + " ASR Notification Policy",
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": ["SNS:Publish"],
            "Resource": topic_arn,
            "Condition": {
                "ArnLike": {"aws:SourceArn": ["arn:aws:s3:::" + bucket_name]},
                "StringEquals": {"aws:SourceAccount": [account_id]},
            },
        }
    ],
}


def test_enable_bucket_event_notifications(mocker):
    sns = boto3.client("sns", config=BOTO_CONFIG)
    stub_sns = Stubber(sns)
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    stub_s3 = Stubber(s3)
    clients = {"sns": sns, "s3": s3}
    stub_sns.add_response(
        "get_topic_attributes",
        {},
        {
            "TopicArn": topic_arn,
        },
    )

    stub_sns.add_response(
        "create_topic",
        {"TopicArn": topic_arn},
        {"Name": topic_name, "Attributes": {"Policy": json.dumps(policy)}},
    )

    stub_s3.add_response(
        "put_bucket_notification_configuration",
        {},
        {
            "Bucket": bucket_name,
            "NotificationConfiguration": {
                "TopicConfigurations": [
                    {
                        "Id": "ASR Bucket Notification Topic Config",
                        "Events": [
                            "s3:ReducedRedundancyLostObject",
                            "s3:ObjectCreated:*",
                            "s3:ObjectRemoved:*",
                            "s3:ObjectRestore:*",
                            "s3:Replication:*",
                            "s3:LifecycleExpiration:*",
                            "s3:LifecycleTransition",
                            "s3:IntelligentTiering",
                            "s3:ObjectTagging:*",
                            "s3:ObjectAcl:Put",
                        ],
                        "TopicArn": topic_arn,
                    }
                ]
            },
        },
    )

    stub_s3.add_response(
        "get_bucket_notification_configuration",
        {
            "TopicConfigurations": [
                {
                    "Id": "ASR Bucket Notification Topic Config",
                    "TopicArn": topic_arn,
                    "Events": [
                        "s3:ReducedRedundancyLostObject",
                        "s3:ObjectCreated:*",
                        "s3:ObjectRemoved:*",
                        "s3:ObjectRestore:*",
                        "s3:Replication:*",
                        "s3:ObjectTagging:*",
                        "s3:ObjectAcl:Put",
                        "s3:LifecycleExpiration:*",
                        "s3:LifecycleTransition",
                        "s3:IntelligentTiering",
                    ],
                }
            ]
        },
        {"Bucket": bucket_name, "ExpectedBucketOwner": account_id},
    )

    stub_sns.activate()

    stub_s3.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {
            "bucket_name": bucket_name,
            "topic_name": topic_name,
            "account_id": account_id,
            "event_types": event_types,
        }
        response = lambda_handler(event, {})
        assert response == {"NotificationARNs": topic_arn}


def test_enable_bucket_event_notifications_topic_exists(mocker):
    sns = boto3.client("sns", config=BOTO_CONFIG)
    stub_sns = Stubber(sns)
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    stub_s3 = Stubber(s3)
    clients = {"sns": sns, "s3": s3}
    received_attributes = {
        "Attributes": {
            "Policy": '{"Version":"2012-10-17","Id":"ASR Notification Policy","Statement":[{"Sid":"test-bucket ASR Notification Policy","Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"SNS:Publish","Resource":"arn:aws:sns:us-east-1:111111111111:SO0111-ASR-S3BucketNotifications","Condition":{"StringEquals":{"aws:SourceAccount":"111111111111"},"ArnLike":{"aws:SourceArn":"arn:aws:s3:::test1"}}}]}',
            "Owner": "111111111111",
            "SubscriptionsPending": "0",
            "TopicArn": "arn:aws:sns:us-east-1:111111111111:testTopic",
            "EffectiveDeliveryPolicy": '{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false,"defaultRequestPolicy":{"headerContentType":"text/plain; charset=UTF-8"}}}',
            "SubscriptionsConfirmed": "0",
            "DisplayName": "",
            "SubscriptionsDeleted": "0",
        }
    }
    stub_sns.add_response(
        "get_topic_attributes",
        received_attributes,
        {
            "TopicArn": topic_arn,
        },
    )

    stub_s3.add_response(
        "put_bucket_notification_configuration",
        {},
        {
            "Bucket": bucket_name,
            "NotificationConfiguration": {
                "TopicConfigurations": [
                    {
                        "Id": "ASR Bucket Notification Topic Config",
                        "Events": [
                            "s3:ReducedRedundancyLostObject",
                            "s3:ObjectCreated:*",
                            "s3:ObjectRemoved:*",
                            "s3:ObjectRestore:*",
                            "s3:Replication:*",
                            "s3:LifecycleExpiration:*",
                            "s3:LifecycleTransition",
                            "s3:IntelligentTiering",
                            "s3:ObjectTagging:*",
                            "s3:ObjectAcl:Put",
                        ],
                        "TopicArn": topic_arn,
                    }
                ]
            },
        },
    )

    stub_s3.add_response(
        "get_bucket_notification_configuration",
        {
            "TopicConfigurations": [
                {
                    "Id": "ASR Bucket Notification Topic Config",
                    "TopicArn": topic_arn,
                    "Events": [
                        "s3:ReducedRedundancyLostObject",
                        "s3:ObjectCreated:*",
                        "s3:ObjectRemoved:*",
                        "s3:ObjectRestore:*",
                        "s3:Replication:*",
                        "s3:ObjectTagging:*",
                        "s3:ObjectAcl:Put",
                        "s3:LifecycleExpiration:*",
                        "s3:LifecycleTransition",
                        "s3:IntelligentTiering",
                    ],
                }
            ]
        },
        {"Bucket": bucket_name, "ExpectedBucketOwner": account_id},
    )

    stub_sns.activate()

    stub_s3.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {
            "bucket_name": bucket_name,
            "topic_name": topic_name,
            "account_id": account_id,
            "event_types": event_types,
        }
        response = lambda_handler(event, {})
        assert response == {"NotificationARNs": topic_arn}


def test_enable_bucket_event_notifications_topic_exists_sid_exists(mocker):
    sns = boto3.client("sns", config=BOTO_CONFIG)
    stub_sns = Stubber(sns)
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    stub_s3 = Stubber(s3)
    clients = {"sns": sns, "s3": s3}
    received_attributes = {
        "Attributes": {
            "Policy": '{"Version":"2012-10-17","Id":"ASR Notification Policy","Statement":[{"Sid":"ASR Notification Policy","Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"SNS:Publish","Resource":"arn:aws:sns:us-east-1:111111111111:SO0111-ASR-S3BucketNotifications","Condition":{"StringEquals":{"aws:SourceAccount":"111111111111"},"ArnLike":{"aws:SourceArn":"arn:aws:s3:::test1"}}}]}',
            "Owner": "111111111111",
            "SubscriptionsPending": "0",
            "TopicArn": "arn:aws:sns:us-east-1:111111111111:testTopic",
            "EffectiveDeliveryPolicy": '{"http":{"defaultHealthyRetryPolicy":{"minDelayTarget":20,"maxDelayTarget":20,"numRetries":3,"numMaxDelayRetries":0,"numNoDelayRetries":0,"numMinDelayRetries":0,"backoffFunction":"linear"},"disableSubscriptionOverrides":false,"defaultRequestPolicy":{"headerContentType":"text/plain; charset=UTF-8"}}}',
            "SubscriptionsConfirmed": "0",
            "DisplayName": "",
            "SubscriptionsDeleted": "0",
        }
    }
    stub_sns.add_response(
        "get_topic_attributes",
        received_attributes,
        {
            "TopicArn": topic_arn,
        },
    )
    topic_attributes_policy = received_attributes["Attributes"]["Policy"]  # str
    topic_attributes_policy_dict = json.loads(topic_attributes_policy)  # dict
    topic_attributes_policy_dict["Statement"].append(policy["Statement"][0])
    new_topic_attributes_policy = json.dumps(topic_attributes_policy_dict)
    stub_sns.add_response(
        "set_topic_attributes",
        {},
        {
            "TopicArn": topic_arn,
            "AttributeName": "Policy",
            "AttributeValue": new_topic_attributes_policy,
        },
    )

    stub_s3.add_response(
        "put_bucket_notification_configuration",
        {},
        {
            "Bucket": bucket_name,
            "NotificationConfiguration": {
                "TopicConfigurations": [
                    {
                        "Id": "ASR Bucket Notification Topic Config",
                        "Events": [
                            "s3:ReducedRedundancyLostObject",
                            "s3:ObjectCreated:*",
                            "s3:ObjectRemoved:*",
                            "s3:ObjectRestore:*",
                            "s3:Replication:*",
                            "s3:LifecycleExpiration:*",
                            "s3:LifecycleTransition",
                            "s3:IntelligentTiering",
                            "s3:ObjectTagging:*",
                            "s3:ObjectAcl:Put",
                        ],
                        "TopicArn": topic_arn,
                    }
                ]
            },
        },
    )

    stub_s3.add_response(
        "get_bucket_notification_configuration",
        {
            "TopicConfigurations": [
                {
                    "Id": "ASR Bucket Notification Topic Config",
                    "TopicArn": topic_arn,
                    "Events": [
                        "s3:ReducedRedundancyLostObject",
                        "s3:ObjectCreated:*",
                        "s3:ObjectRemoved:*",
                        "s3:ObjectRestore:*",
                        "s3:Replication:*",
                        "s3:ObjectTagging:*",
                        "s3:ObjectAcl:Put",
                        "s3:LifecycleExpiration:*",
                        "s3:LifecycleTransition",
                        "s3:IntelligentTiering",
                    ],
                }
            ]
        },
        {"Bucket": bucket_name, "ExpectedBucketOwner": account_id},
    )

    stub_sns.activate()

    stub_s3.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {
            "bucket_name": bucket_name,
            "topic_name": topic_name,
            "account_id": account_id,
            "event_types": event_types,
        }
        response = lambda_handler(event, {})
        assert response == {"NotificationARNs": topic_arn}


def test_error_case(mocker):
    sns = boto3.client("sns", config=BOTO_CONFIG)
    stub_sns = Stubber(sns)
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    stub_s3 = Stubber(s3)
    clients = {"sns": sns, "s3": s3}
    stub_sns.add_response(
        "get_topic_attributes",
        {},
        {
            "TopicArn": topic_arn,
        },
    )

    stub_sns.add_response(
        "create_topic",
        {"TopicArn": topic_arn},
        {"Name": topic_name, "Attributes": {"Policy": json.dumps(policy)}},
    )

    stub_s3.add_response(
        "put_bucket_notification_configuration",
        {},
        {
            "Bucket": bucket_name,
            "NotificationConfiguration": {
                "TopicConfigurations": [
                    {
                        "Id": "ASR Bucket Notification Topic Config",
                        "Events": [
                            "s3:ReducedRedundancyLostObject",
                            "s3:ObjectCreated:*",
                            "s3:ObjectRemoved:*",
                            "s3:ObjectRestore:*",
                            "s3:Replication:*",
                            "s3:LifecycleExpiration:*",
                            "s3:LifecycleTransition",
                            "s3:IntelligentTiering",
                            "s3:ObjectTagging:*",
                            "s3:ObjectAcl:Put",
                        ],
                        "TopicArn": topic_arn,
                    }
                ]
            },
        },
    )

    stub_s3.add_response(
        "get_bucket_notification_configuration",
        {},
        {"Bucket": bucket_name, "ExpectedBucketOwner": account_id},
    )

    stub_sns.activate()

    stub_s3.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {
            "bucket_name": bucket_name,
            "topic_name": topic_name,
            "account_id": account_id,
            "event_types": event_types,
        }
        with pytest.raises(
            RuntimeError,
            match=f"ERROR: {bucket_name} was not configured with notifications",
        ):
            lambda_handler(event, {})
