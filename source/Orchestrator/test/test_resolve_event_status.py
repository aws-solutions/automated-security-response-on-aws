# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for _resolve_event_status and the rollback notification flow.

Moved from test_send_notifications.py to keep that file focused on the
general send_notifications Lambda behavior.
"""
import copy
import json
import os
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import boto3
from layer.event_transformers import Event, Notification
from layer.test.conftest import create_dynamodb_tables
from moto import mock_aws
from pytest_mock import MockerFixture
from send_notifications import _resolve_event_status, lambda_handler

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.client import DynamoDBClient

# ---------------------------------------------------------------------------
# Shared event fixture
# ---------------------------------------------------------------------------

_default_event: Event = {
    "Notification": {
        "State": "SUCCESS",
        "Message": "ASR restored IAM user from backup",
        "RemediationOutput": "Restore completed successfully",
        "StepFunctionsExecutionId": "arn:aws:states:us-east-1:111111111111:execution:TestSM:test-exec-001",
    },
    "Finding": {
        "Compliance": {"SecurityControlId": "GuardDuty.IAMUser"},
        "Id": "arn:aws:guardduty:us-east-1:111111111111:detector/test/finding/test-rollback-001",
        "GeneratorId": "guardduty/finding",
        "AwsAccountId": "111111111111",
        "ProductFields": {},
        "Resources": [
            {
                "Type": "AwsIamAccessKey",
                "Id": "arn:aws:iam::111111111111:user/test-rollback",
                "Region": "us-east-1",
            }
        ],
        "Title": "GuardDuty IAM compromise (test)",
        "Description": "Synthetic rollback event",
    },
    "SecurityStandard": "SC",
    "ControlId": "GuardDuty.IAMUser",
    "CustomActionName": "ASR:Rollback",
}


def _make_event(
    notification: Notification | None = None,
    finding: dict[str, Any] | None = None,
) -> Event:
    return Event(
        Notification=(
            notification
            if notification is not None
            else {"State": "SUCCESS", "Message": "test message"}
        ),
        Finding=finding if finding is not None else {},
    )


# ---------------------------------------------------------------------------
# Helpers — provision moto resources
# ---------------------------------------------------------------------------


def _setup_ssm_parameters() -> None:
    ssm_client = boto3.client("ssm", region_name="us-east-1")
    ssm_client.put_parameter(
        Name="/Solutions/SO0111/version",
        Value="v1.0.0",
        Type="String",
    )
    ssm_client.put_parameter(
        Name="/Solutions/SO0111/sendCloudwatchMetrics",
        Value="yes",
        Type="String",
    )


def _mock_finding_ssm_lookups(mocker: MockerFixture) -> None:
    """Suppress Finding SSM lookups that hit real AWS in tests."""
    mocker.patch(
        "send_notifications.sechub_findings.Finding._get_security_standard_abbreviation_from_ssm",
        return_value=None,
    )
    mocker.patch(
        "send_notifications.sechub_findings.Finding._get_control_remap",
        return_value=None,
    )
    mocker.patch(
        "send_notifications.sechub_findings.Finding._set_playbook_enabled",
        return_value=None,
    )


def _setup_dynamodb_tables_with_seed(
    finding_type: str, finding_id: str, execution_id: str
) -> "DynamoDBClient":
    """Create DDB tables and seed a history row so update_remediation_status_and_history succeeds."""
    os.environ["FINDINGS_TABLE_NAME"] = "test-findings-table"
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"

    dynamodb = create_dynamodb_tables()

    dynamodb.put_item(
        TableName="test-findings-table",
        Item={
            "findingType": {"S": finding_type},
            "findingId": {"S": finding_id},
            "remediationStatus": {"S": "IN_PROGRESS"},
        },
    )
    dynamodb.put_item(
        TableName="test-history-table",
        Item={
            "findingType": {"S": finding_type},
            "findingId#executionId": {"S": f"{finding_id}#{execution_id}"},
            "remediationStatus": {"S": "IN_PROGRESS"},
        },
    )
    return dynamodb  # type: ignore[no-any-return]


def _setup_sns_topic() -> str:
    """Create the ASR SNS topic in moto and return its ARN."""
    sns = boto3.client("sns", region_name="us-east-1")
    response = sns.create_topic(Name="SO0111-ASR_Topic")
    return response["TopicArn"]  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Pure-function tests for _resolve_event_status
# ---------------------------------------------------------------------------


class TestResolveEventStatus:
    """Unit tests for the rollback status normalization helper."""

    def test_returns_uppercased_status_when_no_custom_action(self):
        event = _make_event(notification={"State": "success", "Message": "ok"})
        result = _resolve_event_status(event)
        assert result == "SUCCESS"

    def test_returns_failed_when_rollback_failed(self):
        event = _make_event(notification={"State": "FAILED", "Message": "boom"})
        event["CustomActionName"] = "ASR:Rollback"
        result = _resolve_event_status(event)
        assert result == "ROLLBACK_FAILED"

    def test_normalizes_success_to_rollback_success_for_rollback_action(self):
        event = _make_event(notification={"State": "SUCCESS", "Message": "restored"})
        event["CustomActionName"] = "ASR:Rollback"
        result = _resolve_event_status(event)
        assert result == "ROLLBACK_SUCCESS"

    def test_terminal_non_success_rollback_resolves_to_rollback_failed(self):
        # Any terminal SSM failure state (e.g. a Step Functions timeout) for a
        # rollback resolves to ROLLBACK_FAILED, not the raw state.
        event = _make_event(notification={"State": "TIMEDOUT", "Message": "stuck"})
        event["CustomActionName"] = "ASR:Rollback"
        result = _resolve_event_status(event)
        assert result == "ROLLBACK_FAILED"

    def test_queued_rollback_is_not_failed(self):
        # QUEUED is mid-flight (not terminal) and must not be promoted to a
        # rollback failure.
        event = _make_event(notification={"State": "QUEUED", "Message": "waiting"})
        event["CustomActionName"] = "ASR:Rollback"
        result = _resolve_event_status(event)
        assert result == "QUEUED"

    def test_does_not_promote_success_for_non_rollback_action(self):
        event = _make_event(notification={"State": "SUCCESS", "Message": "ok"})
        event["CustomActionName"] = "Remediate with ASR"
        result = _resolve_event_status(event)
        assert result == "SUCCESS"

    def test_returns_empty_string_when_state_missing(self):
        event: Event = {"Notification": {"Message": "", "State": ""}, "Finding": {}}
        result = _resolve_event_status(event)
        assert result == ""


# ---------------------------------------------------------------------------
# Integration tests — lambda_handler with real DynamoDB + SNS (moto)
# ---------------------------------------------------------------------------


@mock_aws
def test_lambda_handler_persists_rollback_success_for_successful_rollback(mocker):
    """A successful rollback persists ROLLBACK_SUCCESS in DynamoDB and publishes an INFO notification to SNS."""
    # ARRANGE
    _setup_ssm_parameters()

    finding_id = "arn:aws:guardduty:us-east-1:111111111111:detector/test/finding/test-rollback-001"
    finding_type = "GuardDuty.IAMUser"
    execution_id = (
        "arn:aws:states:us-east-1:111111111111:execution:TestSM:test-exec-001"
    )

    dynamodb = _setup_dynamodb_tables_with_seed(finding_type, finding_id, execution_id)
    topic_arn = _setup_sns_topic()

    # Subscribe an SQS queue to the SNS topic so we can inspect the message
    sqs = boto3.client("sqs", region_name="us-east-1")
    queue_url = sqs.create_queue(QueueName="test-sns-queue")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    sns = boto3.client("sns", region_name="us-east-1")
    sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    # Mock metrics (hits external HTTP endpoint) and Security Hub (finding.resolve)
    mocker.patch("send_notifications.CloudWatchMetrics.send_metric", return_value=None)
    mocker.patch("send_notifications.Metrics.send_metrics", return_value=None)
    mock_resolve = mocker.patch(
        "send_notifications.sechub_findings.Finding.resolve", return_value=None
    )
    _mock_finding_ssm_lookups(mocker)

    event = copy.deepcopy(_default_event)

    # ACT
    lambda_handler(event, {})

    # ASSERT — DynamoDB history row has ROLLBACK_SUCCESS status
    history_response = dynamodb.get_item(
        TableName="test-history-table",
        Key={
            "findingType": {"S": finding_type},
            "findingId#executionId": {"S": f"{finding_id}#{execution_id}"},
        },
    )
    assert history_response["Item"]["remediationStatus"]["S"] == "ROLLBACK_SUCCESS"

    # ASSERT — findings table also updated
    finding_response = dynamodb.get_item(
        TableName="test-findings-table",
        Key={
            "findingType": {"S": finding_type},
            "findingId": {"S": finding_id},
        },
    )
    assert finding_response["Item"]["remediationStatus"]["S"] == "ROLLBACK_SUCCESS"

    # ASSERT — SNS notification was published with INFO severity
    messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10).get(
        "Messages", []
    )
    assert len(messages) >= 1
    sns_body = json.loads(messages[0]["Body"])
    notification_content = json.loads(sns_body["Message"])
    assert notification_content["Severity"] == "INFO"
    # Remediation_Status in the SNS payload reflects the raw event state;
    # the ROLLBACK_SUCCESS promotion is verified via the DynamoDB assertions above.
    assert notification_content["Remediation_Status"] == "SUCCESS"

    # ASSERT — finding.resolve() was NOT called (rollbacks should not resolve the finding)
    mock_resolve.assert_not_called()


@mock_aws
def test_lambda_handler_persists_rollback_failed_for_failed_rollback(mocker):
    """A failed rollback persists ROLLBACK_FAILED in DynamoDB and publishes an ERROR notification to SNS."""
    # ARRANGE
    _setup_ssm_parameters()

    finding_id = "arn:aws:guardduty:us-east-1:111111111111:detector/test/finding/test-rollback-fail-001"
    finding_type = "GuardDuty.IAMUser"
    execution_id = (
        "arn:aws:states:us-east-1:111111111111:execution:TestSM:test-exec-fail-001"
    )

    dynamodb = _setup_dynamodb_tables_with_seed(finding_type, finding_id, execution_id)
    topic_arn = _setup_sns_topic()

    sqs = boto3.client("sqs", region_name="us-east-1")
    queue_url = sqs.create_queue(QueueName="test-sns-queue-fail")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    sns = boto3.client("sns", region_name="us-east-1")
    sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    mocker.patch("send_notifications.CloudWatchMetrics.send_metric", return_value=None)
    mocker.patch("send_notifications.Metrics.send_metrics", return_value=None)
    mocker.patch("send_notifications.sechub_findings.Finding.flag", return_value=None)
    _mock_finding_ssm_lookups(mocker)

    event = copy.deepcopy(_default_event)
    event["Notification"]["State"] = "FAILED"
    event["Notification"]["Message"] = "rollback runbook timed out"
    event["Notification"]["StepFunctionsExecutionId"] = execution_id

    # Update finding ID to match
    event["Finding"]["Id"] = finding_id

    # ACT
    lambda_handler(event, {})

    # ASSERT — DynamoDB history row has ROLLBACK_FAILED status
    history_response = dynamodb.get_item(
        TableName="test-history-table",
        Key={
            "findingType": {"S": finding_type},
            "findingId#executionId": {"S": f"{finding_id}#{execution_id}"},
        },
    )
    assert history_response["Item"]["remediationStatus"]["S"] == "ROLLBACK_FAILED"

    # ASSERT — SNS notification was published with ERROR severity
    messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10).get(
        "Messages", []
    )
    assert len(messages) >= 1
    sns_body = json.loads(messages[0]["Body"])
    notification_content = json.loads(sns_body["Message"])
    assert notification_content["Severity"] == "ERROR"


# ---------------------------------------------------------------------------
# RollbackAction operational metric tests
# ---------------------------------------------------------------------------


def _setup_metric_test(
    mocker: MockerFixture, *, finding_suffix: str, is_failure: bool = False
) -> MagicMock:
    """Common setup for RollbackAction metric tests. Returns the mock_send_metrics mock."""
    _setup_ssm_parameters()

    finding_id = f"arn:aws:guardduty:us-east-1:111111111111:detector/test/finding/test-metric-{finding_suffix}"
    finding_type = "GuardDuty.IAMUser"
    execution_id = f"arn:aws:states:us-east-1:111111111111:execution:TestSM:test-metric-{finding_suffix}"

    _setup_dynamodb_tables_with_seed(finding_type, finding_id, execution_id)
    _setup_sns_topic()

    mocker.patch("send_notifications.CloudWatchMetrics.send_metric", return_value=None)
    mock_send_metrics = mocker.patch(
        "send_notifications.Metrics.send_metrics", return_value=None
    )
    if is_failure:
        mocker.patch(
            "send_notifications.sechub_findings.Finding.flag", return_value=None
        )
    else:
        mocker.patch(
            "send_notifications.sechub_findings.Finding.resolve", return_value=None
        )
    _mock_finding_ssm_lookups(mocker)

    return mock_send_metrics


@mock_aws
def test_rollback_success_emits_rollback_action_metric(mocker):
    """A successful rollback emits a RollbackAction metric with Result=success."""
    mock_send_metrics = _setup_metric_test(mocker, finding_suffix="success")
    event = copy.deepcopy(_default_event)

    lambda_handler(event, {})

    mock_send_metrics.assert_called_once()
    metrics_data = mock_send_metrics.call_args[0][0]
    assert "RollbackAction" in metrics_data
    assert metrics_data["RollbackAction"]["Result"] == "success"
    assert metrics_data["RollbackAction"]["FailureMessage"] == ""
    assert metrics_data["RollbackAction"]["FindingType"] == "GuardDuty.IAMUser"


@mock_aws
def test_rollback_failure_emits_rollback_action_metric_with_failure_message(mocker):
    """A failed rollback emits a RollbackAction metric with Result=failed and FailureMessage."""
    mock_send_metrics = _setup_metric_test(
        mocker, finding_suffix="fail", is_failure=True
    )

    event = copy.deepcopy(_default_event)
    event["Notification"]["State"] = "FAILED"
    event["Notification"]["Message"] = "Rollback runbook timed out"
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:111111111111:execution:TestSM:test-metric-fail"
    event["Finding"][
        "Id"
    ] = "arn:aws:guardduty:us-east-1:111111111111:detector/test/finding/test-metric-fail"

    lambda_handler(event, {})

    mock_send_metrics.assert_called_once()
    metrics_data = mock_send_metrics.call_args[0][0]
    assert "RollbackAction" in metrics_data
    assert metrics_data["RollbackAction"]["Result"] == "failed"
    assert (
        metrics_data["RollbackAction"]["FailureMessage"] == "Rollback runbook timed out"
    )
    assert metrics_data["RollbackAction"]["FindingType"] == "GuardDuty.IAMUser"


@mock_aws
def test_non_rollback_does_not_emit_rollback_action_metric(mocker):
    """A standard remediation does NOT emit a RollbackAction metric."""
    mock_send_metrics = _setup_metric_test(mocker, finding_suffix="normal")

    event = copy.deepcopy(_default_event)
    del event["CustomActionName"]

    lambda_handler(event, {})

    mock_send_metrics.assert_called_once()
    metrics_data = mock_send_metrics.call_args[0][0]
    assert "RollbackAction" not in metrics_data
