# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit Test: exec_ssm_doc.py
Run from /deployment/temp/source/Orchestrator after running build-s3-dist.sh
"""
import os

import boto3
from moto import mock_aws
from send_notifications import (
    create_and_send_cloudwatch_metrics,
    lambda_handler,
    set_message_prefix_and_suffix,
)

AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

default_event = {
    "Notification": {
        "State": "SUCCESS",
        "Message": "A Door is Ajar",
        "RemediationOutput": "remediation output.",
    },
    "Finding": {
        "Compliance": {"SecurityControlId": "S3.1"},
        "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/cis-aws-foundations-benchmark/v/3.0.0"
        "/foobar.1/finding/c605d623-ee6b-460d-9deb-0e8c0551d155",
        "GeneratorId": "my-generator-id",
        "AwsAccountId": "111111111111",
        "ProductFields": {},
        "Resources": [
            {
                "Partition": "aws",
                "Type": "AwsS3Bucket",
                "Details": {
                    "AwsS3Bucket": {
                        "OwnerId": "237ffcc0c9da538a83faba8e1171ddd87956bc584225faa98a78e6b67feea739",
                        "CreatedAt": "2024-08-01T15:22:14.000Z",
                        "Name": "aa-hub-s3bucket07682993-yabeybu3hrxh",
                    }
                },
                "Region": "us-east-1",
                "Id": "arn:aws:s3:::aa-hub-s3bucket07682993-yabeybu3hrxh",
            }
        ],
        "Title": "my-title",
        "Description": "my description",
    },
    "SecurityStandard": "AFSBP",
    "ControlId": "foobar.1",
}


def setup(mocker):
    sharr_notification_stub = mocker.stub()
    sharr_notification_stub.notify = mocker.Mock()
    mocker.patch(
        "send_notifications.sechub_findings.SHARRNotification",
        return_value=sharr_notification_stub,
    )
    mocker.patch("send_notifications.CloudWatchMetrics.send_metric", return_value=None)
    mocker.patch("send_notifications.get_account_alias", return_value="myAccount")
    return sharr_notification_stub


def test_resolved(mocker):
    event = default_event
    sharr_notification_stub = setup(mocker)

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1
    assert sharr_notification_stub.message == "A Door is Ajar"
    assert sharr_notification_stub.remediation_output == "remediation output."
    assert (
        sharr_notification_stub.finding_link
        == f"https://{AWS_REGION}.console.aws.amazon.com/securityhub/home?region={AWS_REGION}#/controls/S3.1"
    )
    assert sharr_notification_stub.remediation_account_alias == "myAccount"
    assert sharr_notification_stub.severity == "INFO"


def test_notification_with_ticketing(mocker):
    event = default_event
    event["GenerateTicket"] = {
        "Ok": True,
        "TicketURL": "https://link-to-my-ticket.atlassian.net",
        "ResponseReason": "Success",
    }
    sharr_notification_stub = setup(mocker)

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1
    assert sharr_notification_stub.message == "A Door is Ajar"
    assert sharr_notification_stub.remediation_output == "remediation output."
    assert (
        sharr_notification_stub.finding_link
        == f"https://{AWS_REGION}.console.aws.amazon.com/securityhub/home?region={AWS_REGION}#/controls/S3.1"
    )
    assert sharr_notification_stub.remediation_account_alias == "myAccount"
    assert sharr_notification_stub.severity == "INFO"
    assert (
        sharr_notification_stub.ticket_url == "https://link-to-my-ticket.atlassian.net"
    )


def test_notification_with_ticketing_error(mocker):
    event = default_event
    event["GenerateTicket"] = {"Ok": False, "ResponseReason": "There was an error"}
    sharr_notification_stub = setup(mocker)

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1
    assert sharr_notification_stub.message == "A Door is Ajar"
    assert sharr_notification_stub.remediation_output == "remediation output."
    assert (
        sharr_notification_stub.finding_link
        == f"https://{AWS_REGION}.console.aws.amazon.com/securityhub/home?region={AWS_REGION}#/controls/S3.1"
    )
    assert sharr_notification_stub.remediation_account_alias == "myAccount"
    assert sharr_notification_stub.severity == "INFO"
    assert (
        sharr_notification_stub.ticket_url
        == "Error generating ticket: There was an error - check ticket_generator lambda logs for details"
    )


def test_wrong_standard(mocker):
    event = {
        "Notification": {
            "State": "WRONGSTANDARD",
            "Message": "A Door is Ajar",
            "RemediationOutput": "remediation output.",
        },
        "SecurityStandard": "AFSBP",
        "ControlId": "foobar.1",
    }
    sharr_notification_stub = setup(mocker)

    lambda_handler(event, {})

    assert sharr_notification_stub.severity == "ERROR"


def test_message_prefix_and_suffix():
    event = {
        "Notification": {
            "ExecId": "Test Prefix",
            "AffectedObject": "Test Suffix",
            "RemediationOutput": "remediation output.",
        },
        "SecurityStandard": "AFSBP",
        "ControlId": "foobar.1",
    }
    messagePrefix, messageSuffix = set_message_prefix_and_suffix(event)
    assert messagePrefix == "Test Prefix: "
    assert messageSuffix == " (Test Suffix)"


@mock_aws
def test_create_and_send_cloudwatch_metrics():
    cloudwatch_client = boto3.client("cloudwatch", region_name="us-east-1")
    ssm_client = boto3.client("ssm", region_name="us-east-1")
    os.environ["ENHANCED_METRICS"] = "no"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    ssm_client.put_parameter(
        Name="/Solutions/SO0111/sendCloudwatchMetrics",
        Value="yes",
        Type="String",
    )

    create_and_send_cloudwatch_metrics("Success", "FooBar.1", "myCustomAction")

    metrics = cloudwatch_client.list_metrics(Namespace="ASR")

    assert len(metrics["Metrics"]) == 2
    metric = metrics["Metrics"][0]

    assert metric["MetricName"] == "RemediationOutcome"

    dimensions = metric["Dimensions"]
    assert len(dimensions) == 2
    assert {"Name": "Outcome", "Value": "Success"} in dimensions
    assert {"Name": "CustomActionName", "Value": "myCustomAction"} in dimensions


@mock_aws
def test_create_and_send_enhanced_cloudwatch_metrics():
    cloudwatch_client = boto3.client("cloudwatch", region_name="us-east-1")
    ssm_client = boto3.client("ssm", region_name="us-east-1")
    os.environ["ENHANCED_METRICS"] = "yes"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    ssm_client.put_parameter(
        Name="/Solutions/SO0111/sendCloudwatchMetrics",
        Value="yes",
        Type="String",
    )

    create_and_send_cloudwatch_metrics("Success", "FooBar.1", "myCustomAction")

    metrics = cloudwatch_client.list_metrics(Namespace="ASR")

    assert len(metrics["Metrics"]) == 3
    enhanced_metric = metrics["Metrics"][0]

    assert enhanced_metric["MetricName"] == "RemediationOutcome"

    dimensions = enhanced_metric["Dimensions"]
    assert len(dimensions) == 2
    assert {"Name": "Outcome", "Value": "Success"} in dimensions
    assert {"Name": "ControlId", "Value": "FooBar.1"} in dimensions
