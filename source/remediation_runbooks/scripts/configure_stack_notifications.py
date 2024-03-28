# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Configure a CloudFormation stack with an SNS topic for notifications, creating the topic if it does
not already exist
"""
from time import sleep, time
from typing import TYPE_CHECKING

import boto3
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_sns.client import SNSClient
else:
    SNSClient = object

boto_config = Config(retries={"mode": "standard"})


def lambda_handler(event, _):
    """
    Configure a CloudFormation stack with an SNS topic for notifications,
    creating the topic if it does not already exist

    `event` should have the following keys and values:
    `stack_arn`: the ARN of the CloudFormation stack to be updated
    `topic_name`: the name of the SQS Queue to create and configure for notifications

    `context` is ignored
    """
    stack_arn = event["stack_arn"]
    topic_name = event["topic_name"]
    topic_arn = get_or_create_topic(topic_name)
    configure_notifications(stack_arn, topic_arn)
    wait_for_update(stack_arn)
    return assert_stack_configured(stack_arn, topic_arn)


def get_or_create_topic(topic_name: str) -> str:
    """Get the SQS topic arn for the given topic name, creating it if it does not already exist"""
    sns: SNSClient = boto3.client("sns", config=boto_config)
    response = sns.create_topic(Name=topic_name)
    return response["TopicArn"]


def configure_notifications(stack_arn: str, topic_arn: str) -> None:
    """Configure the stack with ARN `stack_arn` to notify the queue with ARN `topic_arn`"""
    cloudformation = boto3.resource("cloudformation", config=boto_config)
    stack = cloudformation.Stack(stack_arn)
    kwargs = {"UsePreviousTemplate": True, "NotificationARNs": [topic_arn]}
    if stack.parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": param["ParameterKey"], "UsePreviousValue": True}
            for param in stack.parameters
        ]
    if stack.capabilities:
        kwargs["Capabilities"] = stack.capabilities
    stack.update(**kwargs)


class UpdateTimeoutException(Exception):
    """Timed out waiting for the CloudFormation stack to update"""


def wait_for_update(stack_arn: str) -> None:
    """Wait for the stack with ARN `stack_arn` to be in status `UPDATE_COMPLETE`"""
    wait_interval_seconds = 10
    timeout_seconds = 300
    start = time()
    while get_stack_status(stack_arn) != "UPDATE_COMPLETE":
        if time() - start > timeout_seconds:
            raise UpdateTimeoutException("Timed out waiting for stack update")
        wait_seconds(wait_interval_seconds)
        wait_interval_seconds = wait_interval_seconds * 2


def get_stack_status(stack_arn):
    """Get the status of the CloudFormation stack with ARN `stack_arn`"""
    cloudformation = boto3.client("cloudformation", config=boto_config)
    response = cloudformation.describe_stacks(StackName=stack_arn)
    return response["Stacks"][0]["StackStatus"]


def wait_seconds(seconds):
    """Wait for `seconds` seconds"""
    sleep(seconds)


def assert_stack_configured(stack_arn, topic_arn):
    """
    Verify that the CloudFormation stack with ARN `stack_arn` is configured to update the SQS topic
    with ARN `topic_arn`
    """
    cloudformation = boto3.resource("cloudformation", config=boto_config)
    stack = cloudformation.Stack(stack_arn)
    wait_interval_seconds = 10
    timeout_seconds = 300
    start = time()
    while stack.notification_arns != [topic_arn]:
        if time() - start > timeout_seconds:
            raise StackConfigurationFailedException(
                "Timed out waiting for stack configuration to take effect"
            )
        wait_seconds(wait_interval_seconds)
        wait_interval_seconds = wait_interval_seconds * 2
        stack.reload()
    return {"NotificationARNs": stack.notification_arns}


class StackConfigurationFailedException(Exception):
    """An error occurred updating the CloudFormation stack to notify the SQS topic"""
