# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `configure_stack_notifications` remediation script"""
from datetime import datetime
from typing import TYPE_CHECKING, List
from unittest.mock import patch

import boto3
from botocore.stub import Stubber
from configure_stack_notifications import lambda_handler

if TYPE_CHECKING:
    from mypy_boto3_cloudformation.literals import StackStatusType
    from mypy_boto3_cloudformation.type_defs import DescribeStacksOutputTypeDef
else:
    StackStatusType = object
    DescribeStacksOutputTypeDef = object


@patch("boto3.resource")
def test_configures_stack(mock_resource):
    """Update stack called with notification topic ARN"""
    cfn = boto3.client("cloudformation")
    stub_cfn = Stubber(cfn)
    sns = boto3.client("sns")
    stub_sns = Stubber(sns)
    clients = {"cloudformation": cfn, "sns": sns}

    stack_arn = "blah"
    topic_name = "a_topic"
    topic_arn = "topic_arn"

    mock_resource.return_value.Stack.return_value.parameters = None
    mock_resource.return_value.Stack.return_value.capabilities = []
    mock_resource.return_value.Stack.return_value.notification_arns = [topic_arn]

    stub_sns.add_response("create_topic", {"TopicArn": topic_arn}, {"Name": topic_name})
    stub_cfn.add_response(
        "describe_stacks",
        describe_stacks_response(stack_arn, "UPDATE_COMPLETE", [topic_arn]),
        {"StackName": stack_arn},
    )

    stub_cfn.activate()
    stub_sns.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {"stack_arn": stack_arn, "topic_name": topic_name}
        response = lambda_handler(event, {})
        assert response == {"NotificationARNs": [topic_arn]}

    mock_resource.return_value.Stack.return_value.update.assert_called_once_with(
        UsePreviousTemplate=True, NotificationARNs=[topic_arn]
    )


@patch("boto3.resource")
def test_configures_with_parameters(mock_resource):
    """Update stack called stack parameters"""
    cfn = boto3.client("cloudformation")
    stub_cfn = Stubber(cfn)
    sns = boto3.client("sns")
    stub_sns = Stubber(sns)
    clients = {"cloudformation": cfn, "sns": sns}

    stack_arn = "blah"
    topic_name = "a_topic"
    topic_arn = "topic_arn"

    mock_resource.return_value.Stack.return_value.parameters = [
        {"ParameterKey": "a_key", "ParameterValue": "a_value"},
        {"ParameterKey": "another_key", "ResolvedValue": "another_value"},
    ]
    mock_resource.return_value.Stack.return_value.capabilities = []
    mock_resource.return_value.Stack.return_value.notification_arns = [topic_arn]

    stub_sns.add_response("create_topic", {"TopicArn": topic_arn}, {"Name": topic_name})
    stub_cfn.add_response(
        "describe_stacks",
        describe_stacks_response(stack_arn, "UPDATE_COMPLETE", [topic_arn]),
        {"StackName": stack_arn},
    )

    stub_cfn.activate()
    stub_sns.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {"stack_arn": stack_arn, "topic_name": topic_name}
        response = lambda_handler(event, {})
        assert response == {"NotificationARNs": [topic_arn]}

    mock_resource.return_value.Stack.return_value.update.assert_called_once_with(
        UsePreviousTemplate=True,
        Parameters=[
            {"ParameterKey": "a_key", "UsePreviousValue": True},
            {"ParameterKey": "another_key", "UsePreviousValue": True},
        ],
        NotificationARNs=[topic_arn],
    )


@patch("boto3.resource")
def test_configures_with_capabilities(mock_resource):
    """Update stack called with stack capabilities"""
    cfn = boto3.client("cloudformation")
    stub_cfn = Stubber(cfn)
    sns = boto3.client("sns")
    stub_sns = Stubber(sns)
    clients = {"cloudformation": cfn, "sns": sns}

    stack_arn = "blah"
    topic_name = "a_topic"
    topic_arn = "topic_arn"

    mock_resource.return_value.Stack.return_value.parameters = None
    mock_resource.return_value.Stack.return_value.capabilities = [
        "CAPABILITY_IAM",
        "CAPABILITY_NAMED_IAM",
        "CAPABILITY_AUTO_EXPAND",
    ]
    mock_resource.return_value.Stack.return_value.notification_arns = [topic_arn]

    stub_sns.add_response("create_topic", {"TopicArn": topic_arn}, {"Name": topic_name})
    stub_cfn.add_response(
        "describe_stacks",
        describe_stacks_response(stack_arn, "UPDATE_COMPLETE", [topic_arn]),
        {"StackName": stack_arn},
    )

    stub_cfn.activate()
    stub_sns.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {"stack_arn": stack_arn, "topic_name": topic_name}
        response = lambda_handler(event, {})
        assert response == {"NotificationARNs": [topic_arn]}

    mock_resource.return_value.Stack.return_value.update.assert_called_once_with(
        UsePreviousTemplate=True,
        Capabilities=[
            "CAPABILITY_IAM",
            "CAPABILITY_NAMED_IAM",
            "CAPABILITY_AUTO_EXPAND",
        ],
        NotificationARNs=[topic_arn],
    )


def describe_stacks_response(
    stack_arn: str, stack_status: StackStatusType, notification_arns: List[str]
) -> DescribeStacksOutputTypeDef:
    """
    The response from a call to `describe_stacks` with the following properties substituted:

    `stack_arn`: the ID of the stack

    `stack_status`: the status of the stack, one of the following:
    * `CREATE_IN_PROGRESS`
    * `CREATE_FAILED`
    * `CREATE_COMPLETE`
    * `ROLLBACK_IN_PROGRESS`
    * `ROLLBACK_FAILED`
    * `ROLLBACK_COMPLETE`
    * `DELETE_IN_PROGRESS`
    * `DELETE_FAILED`
    * `DELETE_COMPLETE`
    * `UPDATE_IN_PROGRESS`
    * `UPDATE_COMPLETE_CLEANUP_IN_PROGRESS`
    * `UPDATE_COMPLETE`
    * `UPDATE_FAILED`
    * `UPDATE_ROLLBACK_IN_PROGRESS`
    * `UPDATE_ROLLBACK_FAILED`
    * `UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS`
    * `UPDATE_ROLLBACK_COMPLETE`
    * `REVIEW_IN_PROGRESS`
    * `IMPORT_IN_PROGRESS`
    * `IMPORT_COMPLETE`
    * `IMPORT_ROLLBACK_IN_PROGRESS`
    * `IMPORT_ROLLBACK_FAILED`
    * `IMPORT_ROLLBACK_COMPLETE`

    `notification_arns`: the SNS topic ARNs configured for notifications from this stack
    """
    # ignore incorrect type error for missing key NextToken
    return {  # type: ignore[typeddict-item]
        "Stacks": [
            {
                "StackId": stack_arn,
                "StackName": "string",
                "ChangeSetId": "string",
                "Description": "string",
                "Parameters": [],
                "CreationTime": datetime(2015, 1, 1),
                "DeletionTime": datetime(2015, 1, 1),
                "LastUpdatedTime": datetime(2015, 1, 1),
                "RollbackConfiguration": {
                    "RollbackTriggers": [
                        {"Arn": "string", "Type": "string"},
                    ],
                    "MonitoringTimeInMinutes": 123,
                },
                "StackStatus": stack_status,
                "StackStatusReason": "string",
                "DisableRollback": False,
                "NotificationARNs": notification_arns,
                "TimeoutInMinutes": 123,
                "Capabilities": [],
                "Outputs": [],
                "RoleARN": "a_real_role_arn_no_really",
                "Tags": [
                    {"Key": "string", "Value": "string"},
                ],
                "EnableTerminationProtection": False,
                "ParentId": "string",
                "RootId": "string",
                "DriftInformation": {
                    "StackDriftStatus": "IN_SYNC",
                    "LastCheckTimestamp": datetime(2015, 1, 1),
                },
            }
        ],
        "ResponseMetadata": {
            "RequestId": "",
            "HostId": "",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {},
            "RetryAttempts": 0,
        },
    }
