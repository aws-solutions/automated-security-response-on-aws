# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Configure a CloudFormation stack with an SNS topic for notifications, creating the topic if it does
not already exist
"""
import json
from typing import TYPE_CHECKING, List

import boto3
from botocore.config import Config
from botocore.exceptions import UnknownRegionError

if TYPE_CHECKING:
    from mypy_boto3_sns.client import SNSClient
else:
    SNSClient = object

boto_config = Config(retries={"mode": "standard"})


def lambda_handler(event, _):
    """
    Configure a bucket with an SNS topic for notifications,
    creating the topic if it does not already exist

    `event` should have the following keys and values:
    `bucket_name`: the ARN of the CloudFormation stack to be updated
    `topic_name`: the name of the SQS Queue to create and configure for notifications
    `account_id`: account id that contains the bucket that will have event notifications configured
    `event_types`: the list of events that will have notifications alerted on.

    `context` is ignored
    """
    bucket_name = event["bucket_name"]
    topic_name = event["topic_name"]
    account_id = event["account_id"]
    event_types = event["event_types"]
    topic_arn = get_or_create_topic(topic_name, bucket_name, account_id)
    configure_notifications(bucket_name, topic_arn, event_types)
    return assert_bucket_notifcations_configured(bucket_name, account_id)


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


def get_or_create_topic(topic_name: str, bucket_name: str, account_id: str) -> str:
    """Get the SNS topic arn that will be used to configure notifications, creating it if it does not already exist"""
    sns: SNSClient = boto3.client("sns", config=boto_config)
    # get partition and region to buildArn here, replace sourceArn under condition
    session = boto3.session.Session()
    region = session.region_name
    partition = partition_from_region(session)
    expected_topic_arn = f"arn:{partition}:sns:{region}:{account_id}:{topic_name}"
    policy = {
        "Version": "2012-10-17",
        "Id": "ASR Notification Policy",
        "Statement": [
            {
                "Sid": bucket_name + " ASR Notification Policy",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": ["SNS:Publish"],
                "Resource": expected_topic_arn,
                "Condition": {
                    "ArnLike": {
                        "aws:SourceArn": [f"arn:{partition}:s3:::" + bucket_name]
                    },
                    "StringEquals": {"aws:SourceAccount": [account_id]},
                },
            }
        ],
    }

    try:
        topic_attributes = sns.get_topic_attributes(TopicArn=expected_topic_arn)
        topic_attributes_policy = topic_attributes["Attributes"]["Policy"]  # str
        topic_attributes_policy_dict = json.loads(topic_attributes_policy)  # dict
        for statement in topic_attributes_policy_dict["Statement"]:
            if statement["Sid"] == bucket_name + " ASR Notification Policy":
                return expected_topic_arn
        topic_attributes_policy_dict["Statement"].append(policy["Statement"][0])
        new_topic_attributes_policy = json.dumps(topic_attributes_policy_dict)
        response = sns.set_topic_attributes(
            TopicArn=expected_topic_arn,
            AttributeName="Policy",
            AttributeValue=new_topic_attributes_policy,
        )
        return expected_topic_arn
    except Exception:
        string_policy = json.dumps(policy)
        response = sns.create_topic(
            Name=topic_name,
            Attributes={"Policy": string_policy},
        )
    return response["TopicArn"]


def configure_notifications(
    bucket_name: str, topic_arn: str, event_types: List[str]
) -> None:
    """Configure the bucket `bucket_name` to notify the sns topic with ARN `topic_arn`"""
    s3 = boto3.client("s3", config=boto_config)
    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={
            "TopicConfigurations": [
                {
                    "Id": "ASR Bucket Notification Topic Config",
                    "Events": event_types,
                    "TopicArn": topic_arn,
                }
            ]
        },
    )


def assert_bucket_notifcations_configured(bucket_name, account_id):
    """
    Verify that the bucket `bucket_name` is configured to update the SNS topic
    with ARN `topic_arn`
    """
    s3 = boto3.client("s3", config=boto_config)
    notification_configuration = s3.get_bucket_notification_configuration(
        Bucket=bucket_name, ExpectedBucketOwner=account_id
    )
    try:
        return {
            "NotificationARNs": notification_configuration["TopicConfigurations"][0][
                "TopicArn"
            ]
        }
    except Exception:
        raise RuntimeError(
            f"ERROR: {bucket_name} was not configured with notifications"
        )
