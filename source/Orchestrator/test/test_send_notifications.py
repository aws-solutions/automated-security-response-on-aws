# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import copy
import json
import os
import urllib.parse
from datetime import datetime, timedelta
from typing import Any, cast

import boto3
import pytest
from layer.event_transformers import (
    Event,
    Notification,
    is_notified_workflow,
    is_resolved_item,
)
from layer.history_repository import RemediationUpdateRequest, calculate_ttl_timestamp
from layer.remediation_data_service import (
    map_remediation_status,
    update_remediation_status_and_history,
)
from layer.sechub_findings import (
    FindingInfo,
    extract_finding_id,
    extract_security_control_id,
    get_control_id_from_finding_id,
    get_finding_type,
    sanitize_control_id,
)
from layer.test.conftest import create_dynamodb_tables
from moto import mock_aws
from send_notifications import (
    _enrich_notification_with_finding_info,
    _get_followup_message,
    _publish_notification_event,
    _set_if_present,
    _translate_ocsf_packages,
    create_and_send_cloudwatch_metrics,
    format_failure_message,
    format_remediation_output,
    lambda_handler,
    set_message_prefix_and_suffix,
)

default_event: Event = {
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


@pytest.fixture(scope="module", autouse=True)
def setup_aws_region():
    original_region = os.environ.get("AWS_REGION")
    os.environ["AWS_REGION"] = "us-east-1"
    yield
    if original_region:
        os.environ["AWS_REGION"] = original_region
    else:
        os.environ.pop("AWS_REGION", None)


def setup_ssm_parameters():
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
    return ssm_client


def setup_dynamodb_tables():
    dynamodb = create_dynamodb_tables()
    os.environ["FINDINGS_TABLE_NAME"] = "test-findings-table"
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"
    return dynamodb


def setup(mocker, mock_cloudwatch_metrics=True):
    sharr_notification_stub = mocker.stub()
    sharr_notification_stub.notify = mocker.Mock()
    mocker.patch(
        "send_notifications.sechub_findings.ASRNotification",
        return_value=sharr_notification_stub,
    )
    if mock_cloudwatch_metrics:
        mocker.patch(
            "send_notifications.CloudWatchMetrics.send_metric", return_value=None
        )
    mocker.patch("send_notifications.get_account_alias", return_value="myAccount")

    mock_finding = mocker.Mock()
    mock_finding.uuid = "test-uuid"
    mock_finding.description = "test description"
    mock_finding.standard_name = "test standard"
    mock_finding.standard_version = "1.0"
    mock_finding.standard_control = "test control"
    mock_finding.title = "test title"
    mock_finding.region = "us-east-1"
    mock_finding.account_id = "123456789012"
    mock_finding.arn = "arn:aws:securityhub:us-east-1:111111111111:subscription/cis-aws-foundations-benchmark/v/3.0.0/foobar.1/finding/c605d623-ee6b-460d-9deb-0e8c0551d155"
    mocker.patch(
        "send_notifications.sechub_findings.Finding", return_value=mock_finding
    )

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
        == "https://console.aws.amazon.com/securityhub/home?region=us-east-1#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253Aarn%3Aaws%3Asecurityhub%3Aus-east-1%3A111111111111%3Asubscription%2Fcis-aws-foundations-benchmark%2Fv%2F3.0.0%2Ffoobar.1%2Ffinding%2Fc605d623-ee6b-460d-9deb-0e8c0551d155"
    )
    assert sharr_notification_stub.remediation_account_alias == "myAccount"
    assert sharr_notification_stub.severity == "INFO"


def test_notification_with_ticketing(mocker):
    event = default_event
    event["GenerateTicket"] = {
        "Ok": True,
        "TicketURL": "https://link-to-my-ticket.atlassian.net",
        "ResponseCode": "200",
        "ResponseReason": "Success",
    }
    sharr_notification_stub = setup(mocker)

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1
    assert sharr_notification_stub.message == "A Door is Ajar"
    assert sharr_notification_stub.remediation_output == "remediation output."
    assert (
        sharr_notification_stub.finding_link
        == "https://console.aws.amazon.com/securityhub/home?region=us-east-1#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253Aarn%3Aaws%3Asecurityhub%3Aus-east-1%3A111111111111%3Asubscription%2Fcis-aws-foundations-benchmark%2Fv%2F3.0.0%2Ffoobar.1%2Ffinding%2Fc605d623-ee6b-460d-9deb-0e8c0551d155"
    )
    assert sharr_notification_stub.remediation_account_alias == "myAccount"
    assert sharr_notification_stub.severity == "INFO"
    assert (
        sharr_notification_stub.ticket_url == "https://link-to-my-ticket.atlassian.net"
    )


def test_notification_with_ticketing_error(mocker):
    event = default_event
    event["GenerateTicket"] = {
        "Ok": False,
        "TicketURL": "",
        "ResponseCode": "500",
        "ResponseReason": "There was an error",
    }
    sharr_notification_stub = setup(mocker)

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1
    assert sharr_notification_stub.message == "A Door is Ajar"
    assert sharr_notification_stub.remediation_output == "remediation output."
    assert (
        sharr_notification_stub.finding_link
        == "https://console.aws.amazon.com/securityhub/home?region=us-east-1#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253Aarn%3Aaws%3Asecurityhub%3Aus-east-1%3A111111111111%3Asubscription%2Fcis-aws-foundations-benchmark%2Fv%2F3.0.0%2Ffoobar.1%2Ffinding%2Fc605d623-ee6b-460d-9deb-0e8c0551d155"
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
            "SSMExecutionId": "Test Prefix",
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
    setup_ssm_parameters()
    os.environ["ENHANCED_METRICS"] = "no"

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
    setup_ssm_parameters()
    os.environ["ENHANCED_METRICS"] = "yes"

    create_and_send_cloudwatch_metrics("Success", "FooBar.1", "myCustomAction")

    metrics = cloudwatch_client.list_metrics(Namespace="ASR")

    assert len(metrics["Metrics"]) == 3
    enhanced_metric = metrics["Metrics"][0]

    assert enhanced_metric["MetricName"] == "RemediationOutcome"

    dimensions = enhanced_metric["Dimensions"]
    assert len(dimensions) == 2
    assert {"Name": "Outcome", "Value": "Success"} in dimensions
    assert {"Name": "ControlId", "Value": "FooBar.1"} in dimensions


@mock_aws
def test_multi_service_metrics_emitted_for_guardduty():
    """Multi-service controls emit RemediationAttempt under ASR namespace."""
    cloudwatch_client = boto3.client("cloudwatch", region_name="us-east-1")
    setup_ssm_parameters()
    os.environ["ENHANCED_METRICS"] = "no"

    create_and_send_cloudwatch_metrics("SUCCESS", "GuardDuty.IAMUser", "")

    metrics = cloudwatch_client.list_metrics(
        Namespace="ASR", MetricName="RemediationAttempt"
    )
    assert len(metrics["Metrics"]) == 1
    metric = metrics["Metrics"][0]
    assert metric["MetricName"] == "RemediationAttempt"
    dimensions = metric["Dimensions"]
    assert {"Name": "ServiceType", "Value": "GuardDuty"} in dimensions
    assert {"Name": "FindingType", "Value": "GuardDuty.IAMUser"} in dimensions
    assert {"Name": "Outcome", "Value": "SUCCESS"} in dimensions


@mock_aws
def test_multi_service_metrics_emitted_for_rollback():
    """Rollback actions emit both RemediationAttempt and RollbackOutcome under ASR namespace."""
    cloudwatch_client = boto3.client("cloudwatch", region_name="us-east-1")
    setup_ssm_parameters()
    os.environ["ENHANCED_METRICS"] = "no"

    create_and_send_cloudwatch_metrics(
        "ROLLBACK_SUCCESS", "GuardDuty.IAMUser", "ASR:Rollback"
    )

    metrics = cloudwatch_client.list_metrics(Namespace="ASR")
    metric_names = sorted([m["MetricName"] for m in metrics["Metrics"]])
    assert "RemediationAttempt" in metric_names
    assert "RollbackOutcome" in metric_names

    rollback_metric = next(
        m for m in metrics["Metrics"] if m["MetricName"] == "RollbackOutcome"
    )
    dimensions = rollback_metric["Dimensions"]
    assert {"Name": "ServiceType", "Value": "GuardDuty"} in dimensions
    assert {"Name": "Outcome", "Value": "Success"} in dimensions


@mock_aws
def test_multi_service_metrics_not_emitted_for_standard_controls():
    """Standard CSPM controls (e.g. S3.1) do NOT emit RemediationAttempt."""
    cloudwatch_client = boto3.client("cloudwatch", region_name="us-east-1")
    setup_ssm_parameters()
    os.environ["ENHANCED_METRICS"] = "no"

    create_and_send_cloudwatch_metrics("SUCCESS", "S3.1", "")

    metrics = cloudwatch_client.list_metrics(
        Namespace="ASR", MetricName="RemediationAttempt"
    )
    assert len(metrics["Metrics"]) == 0


@mock_aws
def test_send_operational_metrics_with_event_type(mocker):
    # ARRANGE
    setup_ssm_parameters()
    setup_dynamodb_tables()

    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    sharr_notification_stub = setup(mocker)

    event = copy.deepcopy(default_event)
    event["EventType"] = "CustomAction"
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    # ACT
    lambda_handler(event, {})

    # ASSERT
    mock_urlopen.assert_called_once()
    assert sharr_notification_stub.notify.call_count == 1


@mock_aws
def test_send_operational_metrics_without_event_type(mocker):
    # ARRANGE
    setup_ssm_parameters()
    setup_dynamodb_tables()
    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    sharr_notification_stub = setup(mocker)

    event = copy.deepcopy(default_event)
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"
    if "EventType" in event:
        del event["EventType"]

    # ACT
    lambda_handler(event, {})

    # ASSERT
    mock_urlopen.assert_called_once()
    assert sharr_notification_stub.notify.call_count == 1


@mock_aws
def test_process_metrics_includes_failure_message_on_failed_status(mocker):
    """
    Verifies that failure_message is included in metrics when status is FAILED
    (which maps to status_reason = REMEDIATION_FAILED)
    """
    # ARRANGE
    setup_ssm_parameters()
    setup_dynamodb_tables()

    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    setup(mocker)

    failure_message = "Step fails when it is executing remediation script. Error: No security group rules to delete."
    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "FAILED"
    event["Notification"]["RemediationOutput"] = failure_message
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    # ACT
    lambda_handler(event, {})

    # ASSERT
    mock_urlopen.assert_called_once()
    call_args = mock_urlopen.call_args
    request = call_args[0][0]
    import json
    import urllib.parse

    request_data = json.loads(urllib.parse.unquote(request.data.decode("utf-8")))
    assert request_data["Data"]["status"] == "FAILED"
    assert request_data["Data"]["status_reason"] == "REMEDIATION_FAILED"
    expected_failure_message = f"{failure_message} (Check the Systems Manager > Automation console in the member account for more details.)"
    assert request_data["Data"]["failure_message"] == expected_failure_message


@mock_aws
def test_process_metrics_excludes_failure_message_on_success_status(mocker):
    """
    Verifies that failure_message is NOT included in metrics when remediation status is SUCCESS
    """
    # ARRANGE
    setup_ssm_parameters()
    setup_dynamodb_tables()

    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    setup(mocker)

    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "SUCCESS"
    event["Notification"]["RemediationOutput"] = "Remediation completed successfully"
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    # ACT
    lambda_handler(event, {})

    # ASSERT
    mock_urlopen.assert_called_once()
    call_args = mock_urlopen.call_args
    request = call_args[0][0]
    import json
    import urllib.parse

    request_data = json.loads(urllib.parse.unquote(request.data.decode("utf-8")))
    assert request_data["Data"]["status"] == "SUCCESS"
    assert "failure_message" not in request_data["Data"]
    # ai_generated is tagged on every remediation; default registry is empty
    assert request_data["Data"]["ai_generated"] is False


def _parse_metric_payload(mock_urlopen: Any) -> dict[str, Any]:
    """Decodes the metric payload from the captured urlopen request."""
    request = mock_urlopen.call_args[0][0]
    request_data = json.loads(urllib.parse.unquote(request.data.decode("utf-8")))
    return cast(dict[str, Any], request_data["Data"])


def _seed_finding_metric_attributes(
    dynamodb: Any,
    event: Event,
    *,
    first_detected_time: str,
    notifications_enabled: bool,
    deadline_configured: bool,
) -> None:
    """Writes a finding item carrying the metric-enrichment attributes under the same
    key the Orchestrator derives from the event, so _process_metrics reads it back."""
    dynamodb.put_item(
        TableName="test-findings-table",
        Item={
            "findingType": {"S": get_finding_type(cast(dict[str, Any], event))},
            "findingId": {"S": extract_finding_id(cast(dict[str, Any], event))},
            "firstDetectedTime": {"S": first_detected_time},
            "hasFindingNotificationsEnabled": {"BOOL": notifications_enabled},
            "hasFindingRemediationDeadlineConfigured": {"BOOL": deadline_configured},
        },
    )


@mock_aws
def test_process_metrics_includes_finding_attributes_on_success(mocker):
    """
    On a successful remediation, the metric payload includes first_detected_time and the
    notification/deadline configuration flags read from the Findings table.
    """
    # ARRANGE
    setup_ssm_parameters()
    dynamodb = setup_dynamodb_tables()
    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    setup(mocker)

    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "SUCCESS"
    _seed_finding_metric_attributes(
        dynamodb,
        event,
        first_detected_time="2024-01-05T00:00:00Z",
        notifications_enabled=True,
        deadline_configured=False,
    )

    # ACT
    lambda_handler(event, {})

    # ASSERT
    data = _parse_metric_payload(mock_urlopen)
    assert data["status"] == "SUCCESS"
    assert data["first_detected_time"] == "2024-01-05T00:00:00Z"
    assert data["finding_notifications_enabled"] is True
    assert data["finding_remediation_deadline_configured"] is False


@mock_aws
def test_process_metrics_excludes_finding_attributes_on_failure(mocker):
    """
    Finding metric attributes are only enriched for successful remediations, never for
    failures, even when the finding item carries them.
    """
    # ARRANGE
    setup_ssm_parameters()
    dynamodb = setup_dynamodb_tables()
    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    setup(mocker)

    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "FAILED"
    _seed_finding_metric_attributes(
        dynamodb,
        event,
        first_detected_time="2024-01-05T00:00:00Z",
        notifications_enabled=True,
        deadline_configured=True,
    )

    # ACT
    lambda_handler(event, {})

    # ASSERT
    data = _parse_metric_payload(mock_urlopen)
    assert data["status"] == "FAILED"
    assert "first_detected_time" not in data
    assert "finding_notifications_enabled" not in data
    assert "finding_remediation_deadline_configured" not in data


@mock_aws
def test_process_metrics_omits_finding_attributes_when_absent(mocker):
    """
    A successful remediation whose finding item has no metric-enrichment attributes (e.g.
    ingested before the feature) publishes the metric without those fields.
    """
    # ARRANGE
    setup_ssm_parameters()
    setup_dynamodb_tables()
    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    setup(mocker)

    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "SUCCESS"

    # ACT
    lambda_handler(event, {})

    # ASSERT
    data = _parse_metric_payload(mock_urlopen)
    assert data["status"] == "SUCCESS"
    assert "first_detected_time" not in data
    assert "finding_notifications_enabled" not in data
    assert "finding_remediation_deadline_configured" not in data


@mock_aws
def test_process_metrics_still_publishes_when_enrichment_read_fails(mocker):
    """
    A failure reading the finding's metric attributes must not block metric publishing: the
    metric is still sent (without the enrichment fields).
    """
    # ARRANGE
    setup_ssm_parameters()
    setup_dynamodb_tables()
    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    mocker.patch(
        "send_notifications.get_metric_attributes",
        side_effect=Exception("dynamodb unavailable"),
    )
    setup(mocker)

    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "SUCCESS"

    # ACT
    lambda_handler(event, {})

    # ASSERT: metric still published, without the enrichment fields
    mock_urlopen.assert_called_once()
    data = _parse_metric_payload(mock_urlopen)
    assert data["status"] == "SUCCESS"
    assert "first_detected_time" not in data


@mock_aws
def test_process_metrics_excludes_failure_message_on_timedout_status(mocker):
    """
    Verifies that failure_message is NOT included in metrics when status is TIMEDOUT
    (status_reason = REMEDIATION_TIMED_OUT, not REMEDIATION_FAILED)
    """
    # ARRANGE
    setup_ssm_parameters()
    setup_dynamodb_tables()

    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    setup(mocker)

    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "TIMEDOUT"
    event["Notification"]["RemediationOutput"] = "Remediation timed out"
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    # ACT
    lambda_handler(event, {})

    # ASSERT
    mock_urlopen.assert_called_once()
    call_args = mock_urlopen.call_args
    request = call_args[0][0]
    import json
    import urllib.parse

    request_data = json.loads(urllib.parse.unquote(request.data.decode("utf-8")))
    assert request_data["Data"]["status"] == "FAILED"
    assert request_data["Data"]["status_reason"] == "REMEDIATION_TIMED_OUT"
    assert "failure_message" not in request_data["Data"]


def test_calculate_history_ttl_timestamp():

    timestamp = "2024-01-01T00:00:00Z"
    ttl = calculate_ttl_timestamp(timestamp)

    expected_ttl = int(
        (
            datetime.fromisoformat("2024-01-01T00:00:00+00:00") + timedelta(days=365)
        ).timestamp()
    )
    assert ttl == expected_ttl


def test_map_remediation_status():

    assert map_remediation_status("SUCCESS") == "SUCCESS"
    assert map_remediation_status("success") == "SUCCESS"

    assert map_remediation_status("QUEUED") == "IN_PROGRESS"
    assert map_remediation_status("RUNNING") == "IN_PROGRESS"
    assert map_remediation_status("IN_PROGRESS") == "IN_PROGRESS"

    assert map_remediation_status("FAILED") == "FAILED"
    assert map_remediation_status("LAMBDA_ERROR") == "FAILED"
    assert map_remediation_status("TIMEOUT") == "FAILED"
    assert map_remediation_status("CANCELLED") == "FAILED"

    assert map_remediation_status("UNKNOWN_STATUS") == "FAILED"


def test_remediation_update_request_validation():

    # Test valid request
    valid_request = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id",
        remediation_status="SUCCESS",
        finding_type="test-finding-type",
    )
    assert valid_request.validate() is True

    # Test invalid request - missing finding_id
    invalid_request = RemediationUpdateRequest(
        finding_id="",
        execution_id="arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id",
        remediation_status="SUCCESS",
        finding_type="test-finding-type",
    )
    assert invalid_request.validate() is False

    # Test invalid request - missing execution_id
    invalid_request2 = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="",
        remediation_status="SUCCESS",
        finding_type="test-finding-type",
    )
    assert invalid_request2.validate() is False


@mock_aws
def test_update_remediation_status_and_history_success(mocker):

    setup_dynamodb_tables()

    mocker.patch(
        "layer.remediation_data_service.try_update_with_existing_history",
        return_value=True,
    )

    request = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id",
        remediation_status="SUCCESS",
        finding_type="test-finding-type",
    )

    update_remediation_status_and_history(request)


@mock_aws
def test_update_remediation_status_and_history_fallback(mocker):

    setup_dynamodb_tables()

    mocker.patch(
        "layer.remediation_data_service.try_update_with_existing_history",
        return_value=False,
    )
    mocker.patch("layer.remediation_data_service.create_history_with_finding_update")

    request = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id",
        remediation_status="SUCCESS",
        finding_type="test-finding-type",
    )

    update_remediation_status_and_history(request)


@mock_aws
def test_lambda_handler_with_remediation_update(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    sharr_notification_stub = setup(mocker)
    mocker.patch("send_notifications.update_remediation_status_and_history")

    event = copy.deepcopy(default_event)
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1


@mock_aws
def test_update_finding_remediation_status_with_finding_type(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    os.environ["ENHANCED_METRICS"] = "no"

    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )
    setup(mocker)

    event = copy.deepcopy(default_event)
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"
    event["Finding"]["Compliance"]["SecurityControlId"] = "EC2.1"
    event["Finding"][
        "Id"
    ] = "arn:aws:securityhub:us-east-1:123456789012:finding/custom-format/test-id"
    event["Resources"] = [{"Id": "i-1234567890abcdef0", "Type": "AwsEc2Instance"}]
    event["AccountId"] = "123456789012"
    event["Region"] = "us-east-1"
    event["Severity"] = {"Label": "HIGH"}

    lambda_handler(event, {})

    mock_update.assert_called_once()

    call_args = mock_update.call_args.args[0]

    assert call_args.finding_type == "EC2.1"
    assert (
        call_args.finding_id
        == "arn:aws:securityhub:us-east-1:123456789012:finding/custom-format/test-id"
    )
    assert (
        call_args.execution_id
        == "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"
    )
    assert call_args.remediation_status == "SUCCESS"
    assert call_args.resource_id == "i-1234567890abcdef0"
    assert call_args.resource_type == "AwsEc2Instance"
    assert call_args.account_id == "123456789012"
    assert call_args.region == "us-east-1"
    assert call_args.severity == "HIGH"


@mock_aws
def test_history_uses_resource_owner_account_for_access_analyzer(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    os.environ["ENHANCED_METRICS"] = "no"

    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )
    setup(mocker)

    # ARRANGE: IAM Access Analyzer org-analyzer finding where the finding account
    # (admin) differs from the resource-owner account in ProductFields.
    event = copy.deepcopy(default_event)
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:111111111111:execution:TestStateMachine:test-execution-id"
    event["Finding"]["Compliance"][
        "SecurityControlId"
    ] = "IAMAccessAnalyzer.ExternalAccess"
    event["Finding"][
        "Id"
    ] = "arn:aws:access-analyzer:us-east-1:111111111111:analyzer/org-analyzer/arn:aws:kms:us-east-1:222222222222:key/abc"
    event["Finding"]["AwsAccountId"] = "111111111111"
    event["Finding"]["ProductFields"] = {"ResourceOwnerAccount": "222222222222"}
    event["AccountId"] = "111111111111"
    event["Region"] = "us-east-1"
    event["Severity"] = {"Label": "HIGH"}

    # ACT
    lambda_handler(event, {})

    # ASSERT: both the history record and the synthesized ASFF blob use the
    # resource-owner account, not the administrator account.
    import gzip
    import json

    call_args = mock_update.call_args.args[0]
    assert call_args.account_id == "222222222222"
    assert call_args.finding_json is not None
    decompressed = json.loads(gzip.decompress(call_args.finding_json))
    assert decompressed["AwsAccountId"] == "222222222222"


@mock_aws
def test_update_finding_remediation_status_missing_finding_type(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )
    setup(mocker)

    event = copy.deepcopy(default_event)
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    event["Finding"][
        "Id"
    ] = "arn:aws:securityhub:us-east-1:123456789012:finding/custom-format/test-id"
    if "Compliance" in event["Finding"]:
        del event["Finding"]["Compliance"]["SecurityControlId"]
    # With no derivable ASFF/ARN control id and no orchestrator ControlId
    # fallback, the finding type resolves to empty.
    event["ControlId"] = ""

    lambda_handler(event, {})

    mock_update.assert_called_once()

    call_args = mock_update.call_args.args[0]

    assert call_args.finding_type == ""


@mock_aws
def test_update_finding_remediation_status_no_finding_in_event(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )
    setup(mocker)

    event = {
        "Notification": {
            "State": "SUCCESS",
            "Message": "A Door is Ajar",
            "StepFunctionsExecutionId": "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id",
        },
        "SecurityStandard": "AFSBP",
        "ControlId": "foobar.1",
    }

    lambda_handler(event, {})

    mock_update.assert_not_called()


def test_get_control_id_from_finding_id():
    unconsolidated_id = "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.13/finding/abc123"
    result = get_control_id_from_finding_id(unconsolidated_id)
    assert result == "aws-foundational-security-best-practices/v/1.0.0/S3.13"

    consolidated_id = "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.13/finding/abc123"
    result = get_control_id_from_finding_id(consolidated_id)
    assert result == "security-control/S3.13"

    invalid_id = "invalid-finding-id"
    result = get_control_id_from_finding_id(invalid_id)
    assert result is None


def test_sanitize_control_id():
    assert sanitize_control_id("S3.13") == "S3.13"

    assert sanitize_control_id("S3@13#test!") == "S313test"

    assert (
        sanitize_control_id("aws-foundational/v1.0.0/S3.13")
        == "aws-foundational/v1.0.0/S3.13"
    )


def test_extract_security_control_id_fallback():
    # extract_security_control_id takes dict[str, Any], not Event, so we build
    # plain dicts here — no need to bounce through the Event TypedDict.
    event_with_compliance: dict[str, Any] = {
        "Finding": {
            "Compliance": {"SecurityControlId": "S3.13"},
            "ProductFields": {"ControlId": "S3.14"},
        }
    }
    result = extract_security_control_id(event_with_compliance)
    assert result == "S3.13"

    event_with_fallback: dict[str, Any] = {
        "Finding": {
            "Compliance": {"SecurityControlId": ""},
            "ProductFields": {"ControlId": "S3.14"},
        }
    }
    result = extract_security_control_id(event_with_fallback)
    assert result == "S3.14"

    event_no_finding: dict[str, Any] = {}
    result = extract_security_control_id(event_no_finding)
    assert result == ""


def test_get_finding_type_comprehensive():
    # get_finding_type takes dict[str, Any]; build plain dicts directly.
    event_with_finding_id: dict[str, Any] = {
        "Finding": {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.15/finding/abc123",
            "Compliance": {"SecurityControlId": "S3.13"},
            "ProductFields": {"ControlId": "S3.14"},
        }
    }
    result = get_finding_type(event_with_finding_id)
    assert result == "security-control/S3.15"

    event_compliance_fallback: dict[str, Any] = {
        "Finding": {
            "Id": "invalid-finding-id",
            "Compliance": {"SecurityControlId": "S3.13"},
            "ProductFields": {"ControlId": "S3.14"},
        }
    }
    result = get_finding_type(event_compliance_fallback)
    assert result == "S3.13"

    event_product_fields_fallback: dict[str, Any] = {
        "Finding": {
            "Id": "invalid-finding-id",
            "Compliance": {"SecurityControlId": ""},
            "ProductFields": {"ControlId": "S3.14"},
        }
    }
    result = get_finding_type(event_product_fields_fallback)
    assert result == "S3.14"

    event_no_control_id: dict[str, Any] = {
        "Finding": {
            "Id": "invalid-finding-id",
            "Compliance": {},
            "ProductFields": {},
        }
    }
    result = get_finding_type(event_no_control_id)
    assert result == ""


def test_is_notified_workflow():
    # Test NOTIFIED workflow with regular event type
    notified_event = _make_event(
        finding={
            "Workflow": {"Status": "NOTIFIED"},
            "Id": "test-finding-id",
        },
    )
    notified_event["EventType"] = "Security Hub Findings - Imported"
    assert is_notified_workflow(notified_event) is True

    # Test NOTIFIED workflow with Custom Action event type - should return False
    notified_custom_action_event = _make_event(
        finding={
            "Workflow": {"Status": "NOTIFIED"},
            "Id": "test-finding-id",
        },
    )
    notified_custom_action_event["EventType"] = "Security Hub Findings - Custom Action"
    assert is_notified_workflow(notified_custom_action_event) is False

    # Test NOTIFIED workflow with API Action event type - should return False
    notified_api_action_event = _make_event(
        finding={
            "Workflow": {"Status": "NOTIFIED"},
            "Id": "test-finding-id",
        },
    )
    notified_api_action_event["EventType"] = "Security Hub Findings - API Action"
    assert is_notified_workflow(notified_api_action_event) is False

    # Test NOTIFIED workflow without EventType - should return True
    notified_no_event_type = _make_event(
        finding={
            "Workflow": {"Status": "NOTIFIED"},
            "Id": "test-finding-id",
        },
    )
    assert is_notified_workflow(notified_no_event_type) is True

    # Test non-NOTIFIED workflow
    new_event = _make_event(
        finding={
            "Workflow": {"Status": "NEW"},
            "Id": "test-finding-id",
        },
    )
    assert is_notified_workflow(new_event) is False

    # Test missing workflow
    no_workflow_event = _make_event(finding={"Id": "test-finding-id"})
    assert is_notified_workflow(no_workflow_event) is False

    # Test empty workflow
    empty_workflow_event = _make_event(
        finding={
            "Workflow": {},
            "Id": "test-finding-id",
        },
    )
    assert is_notified_workflow(empty_workflow_event) is False

    # Test no finding
    # _make_event() gives us Finding={} by default, which for this helper is
    # indistinguishable from "Finding key missing": no Workflow inside either way.
    no_finding_event = _make_event()
    assert is_notified_workflow(no_finding_event) is False

    # Test workflow is not a dict
    invalid_workflow_event = _make_event(
        finding={
            "Workflow": "NOTIFIED",  # String instead of dict
            "Id": "test-finding-id",
        },
    )
    assert is_notified_workflow(invalid_workflow_event) is False


@mock_aws
def test_lambda_handler_with_product_fields_fallback(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    sharr_notification_stub = setup(mocker)
    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )

    event = copy.deepcopy(default_event)
    event["Finding"][
        "Id"
    ] = "arn:aws:securityhub:us-east-1:123456789012:finding/custom-format/test-id"
    event["Finding"]["Compliance"]["SecurityControlId"] = ""  # Empty
    event["Finding"]["ProductFields"]["ControlId"] = "S3.13"  # Fallback value
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1
    assert (
        sharr_notification_stub.finding_link
        == "https://console.aws.amazon.com/securityhub/home?region=us-east-1#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253Aarn%3Aaws%3Asecurityhub%3Aus-east-1%3A111111111111%3Asubscription%2Fcis-aws-foundations-benchmark%2Fv%2F3.0.0%2Ffoobar.1%2Ffinding%2Fc605d623-ee6b-460d-9deb-0e8c0551d155"
    )

    mock_update.assert_called_once()
    call_args = mock_update.call_args.args[0]
    assert call_args.finding_type == "S3.13"


@mock_aws
def test_lambda_handler_notified_workflow_skips_database_updates(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    sharr_notification_stub = setup(mocker)
    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )

    event = copy.deepcopy(default_event)
    event["Finding"]["Workflow"] = {
        "Status": "NOTIFIED"
    }  # Set NOTIFIED workflow status
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1

    mock_update.assert_not_called()


@mock_aws
def test_lambda_handler_non_notified_workflow_updates_database(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    sharr_notification_stub = setup(mocker)
    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )

    event = copy.deepcopy(default_event)
    event["Finding"]["Workflow"] = {"Status": "NEW"}  # Set non-NOTIFIED workflow status
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1

    mock_update.assert_called_once()


def test_security_hub_v2_enabled_finding_link(mocker):
    mocker.patch.dict("os.environ", {"SECURITY_HUB_V2_ENABLED": "true"})
    event = default_event
    sharr_notification_stub = setup(mocker)

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1
    assert (
        sharr_notification_stub.finding_link
        == "https://console.aws.amazon.com/securityhub/v2/home?region=us-east-1#/findings?search=finding_info.uid%3D%255Coperator%255C%253AEQUALS%255C%253Aarn%3Aaws%3Asecurityhub%3Aus-east-1%3A111111111111%3Asubscription%2Fcis-aws-foundations-benchmark%2Fv%2F3.0.0%2Ffoobar.1%2Ffinding%2Fc605d623-ee6b-460d-9deb-0e8c0551d155"
    )


def test_should_override_to_success_with_not_new_and_resolved():
    event = _make_event(
        notification={
            "State": "NOT_NEW",
            "Message": "Finding Workflow State is not NEW (RESOLVED).",
        },
        finding={
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/test/finding/123",
            "Workflow": {"Status": "RESOLVED"},
        },
    )

    result = is_resolved_item(event)

    assert result is True


def test_should_override_to_success_with_different_state():
    event = _make_event(
        notification={
            "State": "QUEUED",
            "Message": "Remediation queued",
        },
        finding={
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/test/finding/123",
            "Workflow": {"Status": "RESOLVED"},
        },
    )

    result = is_resolved_item(event)

    assert result is False


def test_should_override_to_success_with_different_workflow_status():
    event = _make_event(
        notification={
            "State": "NOT_NEW",
            "Message": "Finding Workflow State is not NEW (NOTIFIED).",
        },
        finding={
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/test/finding/123",
            "Workflow": {"Status": "NOTIFIED"},
        },
    )

    result = is_resolved_item(event)

    assert result is False


def test_should_override_to_success_without_finding():
    # Exercise the defensive branch ``"Finding" not in event`` in
    # is_resolved_item. The production contract requires Finding, but we test
    # the guard that protects against malformed inputs. A single cast is
    # justified here because the whole point is to violate the type contract.
    event_without_finding: Event = cast(
        Event,
        {
            "Notification": {
                "State": "NOT_NEW",
                "Message": "Test message",
            },
        },
    )

    result = is_resolved_item(event_without_finding)

    assert result is False

    del os.environ["FINDINGS_TABLE_NAME"]
    del os.environ["HISTORY_TABLE_NAME"]


@mock_aws
def test_lambda_handler_overrides_status_for_resolved_workflow(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    sharr_notification_stub = setup(mocker)
    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )

    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "NOT_NEW"
    event["Notification"]["Message"] = "Finding Workflow State is not NEW (RESOLVED)."
    event["Finding"]["Workflow"] = {"Status": "RESOLVED"}
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1

    mock_update.assert_called_once()

    call_args = mock_update.call_args[0][0]
    assert call_args.remediation_status == "SUCCESS"
    assert call_args.error is None


@mock_aws
def test_lambda_handler_with_stepfunctions_failure_event(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    sharr_notification_stub = setup(mocker)

    raw_event = {
        "detail-type": "Step Functions Execution Status Change",
        "detail": {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution",
            "status": "FAILED",
            "cause": "Lambda function failed",
            "input": '{"detail": {"findings": [{"Id": "test-finding-id", "Compliance": {"SecurityControlId": "EC2.1"}}]}}',
        },
    }

    lambda_handler(raw_event, {})

    assert sharr_notification_stub.notify.call_count == 1
    assert sharr_notification_stub.severity == "ERROR"


@mock_aws
def test_lambda_handler_queued_notification_creates_history_without_finding(mocker):
    setup_ssm_parameters()
    dynamodb = setup_dynamodb_tables()
    cloudwatch_client = boto3.client("cloudwatch", region_name="us-east-1")

    os.environ["ENHANCED_METRICS"] = "no"

    sharr_notification_stub = setup(mocker, mock_cloudwatch_metrics=False)

    event = _make_event(
        notification={
            "State": "QUEUED",
            "Message": "Remediation queued",
            "StepFunctionsExecutionId": "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id",
        },
        finding={
            "Id": "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/test-finding-id",
            "Compliance": {"SecurityControlId": "S3.1"},
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Severity": {"Label": "HIGH"},
            "Resources": [{"Id": "arn:aws:s3:::test-bucket", "Type": "AwsS3Bucket"}],
        },
    )
    event["SSMExecution"] = {
        "Account": "123456789012",
        "Region": "us-east-1",
    }

    lambda_handler(event, {})

    history_response = dynamodb.get_item(
        TableName="test-history-table",
        Key={
            "findingType": {"S": "security-control/S3.1"},
            "findingId#executionId": {
                "S": "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/test-finding-id#arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"
            },
        },
    )

    assert "Item" in history_response
    assert history_response["Item"]["remediationStatus"]["S"] == "IN_PROGRESS"
    assert history_response["Item"]["accountId"]["S"] == "123456789012"
    assert history_response["Item"]["region"]["S"] == "us-east-1"
    assert history_response["Item"]["severity"]["S"] == "HIGH"
    assert history_response["Item"]["resourceId"]["S"] == "arn:aws:s3:::test-bucket"

    assert sharr_notification_stub.notify.call_count == 1
    assert sharr_notification_stub.message == "Remediation queued"
    assert sharr_notification_stub.severity == "INFO"

    metrics = cloudwatch_client.list_metrics(Namespace="ASR")
    assert len(metrics["Metrics"]) == 1


@mock_aws
def test_lambda_handler_queued_notification_updates_existing_history(mocker):
    setup_ssm_parameters()
    dynamodb = setup_dynamodb_tables()
    cloudwatch_client = boto3.client("cloudwatch", region_name="us-east-1")

    os.environ["ENHANCED_METRICS"] = "no"

    dynamodb.put_item(
        TableName="test-history-table",
        Item={
            "findingType": {"S": "security-control/S3.1"},
            "findingId#executionId": {
                "S": "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/test-finding-id#arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"
            },
            "remediationStatus": {"S": "QUEUED"},
        },
    )

    sharr_notification_stub = setup(mocker, mock_cloudwatch_metrics=False)

    event = _make_event(
        notification={
            "State": "QUEUED",
            "Message": "Remediation status updated",
            "StepFunctionsExecutionId": "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id",
        },
        finding={
            "Id": "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/test-finding-id",
            "Compliance": {"SecurityControlId": "S3.1"},
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Severity": {"Label": "HIGH"},
            "Resources": [{"Id": "arn:aws:s3:::test-bucket", "Type": "AwsS3Bucket"}],
        },
    )
    event["SSMExecution"] = {
        "Account": "123456789012",
        "Region": "us-east-1",
    }

    lambda_handler(event, {})

    history_response = dynamodb.get_item(
        TableName="test-history-table",
        Key={
            "findingType": {"S": "security-control/S3.1"},
            "findingId#executionId": {
                "S": "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/test-finding-id#arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"
            },
        },
    )

    assert "Item" in history_response
    assert history_response["Item"]["remediationStatus"]["S"] == "IN_PROGRESS"

    assert sharr_notification_stub.notify.call_count == 1
    assert sharr_notification_stub.message == "Remediation status updated"
    assert sharr_notification_stub.severity == "INFO"

    metrics = cloudwatch_client.list_metrics(Namespace="ASR")
    assert len(metrics["Metrics"]) == 1


class TestFormatFailureMessage:
    """Tests for the format_failure_message function"""

    def test_removes_prefix_and_suffix(self):
        # ARRANGE
        raw_message = (
            "Step fails when it is Poll action status for completion. "
            "RuntimeError: Could not find rules to delete. "
            "Please refer to Automation Service Troubleshooting Guide for more diagnosis details."
        )

        # ACT
        result = format_failure_message(raw_message)

        # ASSERT
        expected = (
            "RuntimeError: Could not find rules to delete. "
            "(Check the Systems Manager > Automation console in the member account for more details.)"
        )
        assert result == expected

    def test_collapses_whitespace_and_newlines(self):
        # ARRANGE
        raw_message = (
            "RuntimeError: First line of error\n"
            "Second line of error\n"
            "Third line of error. "
            "Please refer to Automation Service Troubleshooting Guide for more diagnosis details."
        )

        # ACT
        result = format_failure_message(raw_message)

        # ASSERT
        expected = (
            "RuntimeError: First line of error Second line of error Third line of error. "
            "(Check the Systems Manager > Automation console in the member account for more details.)"
        )
        assert result == expected

    def test_handles_traceback_in_message(self):
        # ARRANGE
        raw_message = (
            "Step fails when it is Poll action status for completion. "
            "Traceback (most recent call last):\n\n"
            '  File "/tmp/script.py", line 46, in lambda_handler\n'
            "    raise RuntimeError(\n\n"
            "RuntimeError: Could not find rules to delete for Security Group sg-068c63fb91e6e7427. Please check the inbound rules manually.\n\n"
            "RuntimeError - Could not find rules to delete for Security Group sg-068c63fb91e6e7427. Please check the inbound rules manually.. "
            "Please refer to Automation Service Troubleshooting Guide for more diagnosis details."
        )

        # ACT
        result = format_failure_message(raw_message)

        # ASSERT
        expected = (
            'Traceback (most recent call last): File "/tmp/script.py", line 46, in lambda_handler raise RuntimeError( '
            "RuntimeError: Could not find rules to delete for Security Group sg-068c63fb91e6e7427. Please check the inbound rules manually. "
            "RuntimeError - Could not find rules to delete for Security Group sg-068c63fb91e6e7427. Please check the inbound rules manually.. "
            "(Check the Systems Manager > Automation console in the member account for more details.)"
        )
        assert result == expected

    def test_removes_suffix_only(self):
        # ARRANGE
        raw_message = (
            "Step failed with unknown error. "
            "Please refer to Automation Service Troubleshooting Guide for more diagnosis details."
        )

        # ACT
        result = format_failure_message(raw_message)

        # ASSERT
        expected = (
            "Step failed with unknown error. "
            "(Check the Systems Manager > Automation console in the member account for more details.)"
        )
        assert result == expected

    def test_handles_message_without_prefix_or_suffix(self):
        # ARRANGE
        raw_message = "Some generic failure message without exception pattern"

        # ACT
        result = format_failure_message(raw_message)

        # ASSERT
        expected = (
            "Some generic failure message without exception pattern "
            "(Check the Systems Manager > Automation console in the member account for more details.)"
        )
        assert result == expected

    def test_handles_empty_message(self):
        # ARRANGE
        # ACT
        result = format_failure_message("")

        # ASSERT
        assert result == ""

    def test_includes_execution_id_when_provided(self):
        # ARRANGE
        raw_message = "RuntimeError: Could not find rules to delete."
        execution_id = "12345678-1234-1234-1234-123456789012"

        # ACT
        result = format_failure_message(raw_message, execution_id)

        # ASSERT
        expected = (
            "RuntimeError: Could not find rules to delete. "
            "(Check the Systems Manager > Automation console in the member account for more details. "
            f"The Automation Execution Id is {execution_id})"
        )
        assert result == expected

    def test_excludes_execution_id_when_not_provided(self):
        # ARRANGE
        raw_message = "RuntimeError: Could not find rules to delete."

        # ACT
        result = format_failure_message(raw_message, None)

        # ASSERT
        expected = (
            "RuntimeError: Could not find rules to delete. "
            "(Check the Systems Manager > Automation console in the member account for more details.)"
        )
        assert result == expected

    def test_includes_execution_id_with_prefix_and_suffix_removal(self):
        # ARRANGE
        raw_message = (
            "Step fails when it is Poll action status for completion. "
            "RuntimeError: Could not find rules to delete. "
            "Please refer to Automation Service Troubleshooting Guide for more diagnosis details."
        )
        execution_id = "abcd1234-5678-90ab-cdef-1234567890ab"

        # ACT
        result = format_failure_message(raw_message, execution_id)

        # ASSERT
        expected = (
            "RuntimeError: Could not find rules to delete. "
            "(Check the Systems Manager > Automation console in the member account for more details. "
            f"The Automation Execution Id is {execution_id})"
        )
        assert result == expected


@mock_aws
def test_process_metrics_formats_failure_message(mocker):
    """
    Verifies that failure_message is formatted before being included in metrics
    when status_reason is REMEDIATION_FAILED
    """
    # ARRANGE
    setup_ssm_parameters()
    setup_dynamodb_tables()

    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    setup(mocker)

    raw_failure_message = (
        "Step fails when it is Poll action status for completion. "
        "Traceback (most recent call last):\n\n"
        '  File "/tmp/script.py", line 46, in lambda_handler\n'
        "    raise RuntimeError(\n\n"
        "RuntimeError: Could not find rules to delete. "
        "Please refer to Automation Service Troubleshooting Guide for more diagnosis details."
    )
    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "FAILED"
    event["Notification"]["RemediationOutput"] = raw_failure_message
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    # ACT
    lambda_handler(event, {})

    # ASSERT
    mock_urlopen.assert_called_once()
    call_args = mock_urlopen.call_args
    request = call_args[0][0]
    import json
    import urllib.parse

    request_data = json.loads(urllib.parse.unquote(request.data.decode("utf-8")))
    assert request_data["Data"]["status"] == "FAILED"
    assert request_data["Data"]["status_reason"] == "REMEDIATION_FAILED"
    expected_message = (
        'Traceback (most recent call last): File "/tmp/script.py", line 46, in lambda_handler raise RuntimeError( '
        "RuntimeError: Could not find rules to delete. "
        "(Check the Systems Manager > Automation console in the member account for more details.)"
    )
    assert request_data["Data"]["failure_message"] == expected_message


def test_notification_formats_remediation_output(mocker):
    """
    Verifies that remediation_output is formatted for email notifications
    """
    # ARRANGE
    raw_failure_message = (
        "Step fails when it is Poll action status for completion. "
        "RuntimeError: Security group rule deletion failed. "
        "Please refer to Automation Service Troubleshooting Guide for more diagnosis details."
    )
    event = copy.deepcopy(default_event)
    event["Notification"]["State"] = "FAILED"
    event["Notification"]["RemediationOutput"] = raw_failure_message

    sharr_notification_stub = setup(mocker)

    # ACT
    lambda_handler(event, {})

    # ASSERT
    expected_output = (
        "RuntimeError: Security group rule deletion failed. "
        "(Check the Systems Manager > Automation console in the member account for more details.)"
    )
    assert sharr_notification_stub.remediation_output == expected_output


class TestFormatRemediationOutput:
    """Tests for the format_remediation_output function"""

    def test_format_success_output_decodes_nested_json(self):
        # ARRANGE
        raw_output = '{"EnableAPIGatewayExecutionLogs.Output": ["{\\"Message\\":\\"successfully enabled execution logging at INFO for stage prod\\",\\"LoggingLevel\\":\\"INFO\\",\\"ApiId\\":\\"6y0uupx5m8\\"}"]}'

        # ACT
        result = format_remediation_output(raw_output, control_runbook_status="SUCCESS")

        # ASSERT
        assert isinstance(result, dict)
        assert result == {
            "EnableAPIGatewayExecutionLogs.Output": {
                "Message": "successfully enabled execution logging at INFO for stage prod",
                "LoggingLevel": "INFO",
                "ApiId": "6y0uupx5m8",
            }
        }

    def test_format_success_output_handles_multiple_keys(self):
        # ARRANGE
        raw_output = '{"Step1.Output": ["{\\"status\\": \\"ok\\"}"], "Step2.Output": ["{\\"count\\": 5}"]}'

        # ACT
        result = format_remediation_output(raw_output, control_runbook_status="SUCCESS")

        # ASSERT
        assert isinstance(result, dict)
        assert result["Step1.Output"] == {"status": "ok"}
        assert result["Step2.Output"] == {"count": 5}

    def test_format_failure_output_with_failed_status(self):
        # ARRANGE
        raw_output = "RuntimeError: Something went wrong. Please refer to Automation Service Troubleshooting Guide for more diagnosis details."

        # ACT
        result = format_remediation_output(raw_output, control_runbook_status="FAILED")

        # ASSERT
        expected = (
            "RuntimeError: Something went wrong. "
            "(Check the Systems Manager > Automation console in the member account for more details.)"
        )
        assert result == expected

    def test_format_failure_output_with_timedout_status(self):
        # ARRANGE
        raw_output = "Step execution timed out after 600 seconds"

        # ACT
        result = format_remediation_output(
            raw_output, control_runbook_status="TIMEDOUT"
        )

        # ASSERT
        # TIMEDOUT is not FAILED, so it should return raw output without formatting
        assert result == raw_output

    def test_format_failure_output_with_cancelled_status(self):
        # ARRANGE
        raw_output = "Execution was cancelled by user"

        # ACT
        result = format_remediation_output(
            raw_output, control_runbook_status="CANCELLED"
        )

        # ASSERT
        # CANCELLED is not FAILED, so it should return raw output without formatting
        assert result == raw_output

    def test_format_failure_output_includes_execution_id(self):
        # ARRANGE
        raw_output = "RuntimeError: Database connection failed"
        execution_id = "abc-123-def-456"

        # ACT
        result = format_remediation_output(
            raw_output,
            control_runbook_execution_id=execution_id,
            control_runbook_status="FAILED",
        )

        # ASSERT
        expected = (
            "RuntimeError: Database connection failed "
            f"(Check the Systems Manager > Automation console in the member account for more details. "
            f"The Automation Execution Id is {execution_id})"
        )
        assert result == expected

    def test_format_success_with_plain_text_output(self):
        # ARRANGE
        raw_output = "Operation completed successfully"

        # ACT
        result = format_remediation_output(raw_output, control_runbook_status="SUCCESS")

        # ASSERT
        # Plain text with SUCCESS status should be returned as-is (no debugging tip)
        assert result == "Operation completed successfully"

    def test_format_without_status_falls_back_to_structure_detection(self):
        # ARRANGE
        # Plain text that looks like an error (no status provided)
        raw_output = "RuntimeError: Something went wrong. Please refer to Automation Service Troubleshooting Guide for more diagnosis details."

        # ACT
        result = format_remediation_output(raw_output)

        # ASSERT
        # Without status and non-JSON input, returns raw output as-is
        assert result == raw_output

    def test_format_without_status_decodes_json(self):
        # ARRANGE
        raw_output = '{"Step1.Output": ["{\\"status\\": \\"ok\\"}"]}'

        # ACT
        result = format_remediation_output(raw_output)

        # ASSERT
        assert isinstance(result, dict)
        assert result["Step1.Output"] == {"status": "ok"}

    def test_format_empty_output(self):
        # ARRANGE
        # ACT
        result = format_remediation_output("")

        # ASSERT
        assert result == ""

    def test_format_output_with_non_json_list_value(self):
        # ARRANGE
        raw_output = '{"SomeStep.Output": ["not a json string"]}'

        # ACT
        result = format_remediation_output(raw_output, control_runbook_status="SUCCESS")

        # ASSERT
        assert isinstance(result, dict)
        assert result["SomeStep.Output"] == ["not a json string"]

    def test_format_json_output_with_failed_status_formats_as_failure(self):
        # ARRANGE
        # Even if output is valid JSON, FAILED status should format as failure
        raw_output = '{"error": "Something went wrong"}'

        # ACT
        result = format_remediation_output(raw_output, control_runbook_status="FAILED")

        # ASSERT
        expected = (
            '{"error": "Something went wrong"} '
            "(Check the Systems Manager > Automation console in the member account for more details.)"
        )
        assert result == expected

    def test_format_handles_case_insensitive_status(self):
        # ARRANGE
        raw_output = "Error occurred"

        # ACT - test lowercase status
        result = format_remediation_output(raw_output, control_runbook_status="failed")

        # ASSERT
        expected = (
            "Error occurred "
            "(Check the Systems Manager > Automation console in the member account for more details.)"
        )
        assert result == expected


class TestSetIfPresent:
    """Tests for the _set_if_present helper function"""

    def test_sets_value_when_not_none(self):
        target: dict[str, str] = {}
        _set_if_present(target, "key", "value")
        assert target == {"key": "value"}

    def test_skips_when_value_is_none(self):
        target: dict[str, str] = {"existing": "data"}
        _set_if_present(target, "key", None)
        assert target == {"existing": "data"}

    def test_overwrites_existing_key(self):
        target: dict[str, str] = {"key": "old"}
        _set_if_present(target, "key", "new")
        assert target == {"key": "new"}

    def test_sets_empty_string(self):
        target: dict[str, str] = {}
        _set_if_present(target, "key", "")
        assert target == {"key": ""}


class TestEnrichNotificationWithFindingInfo:
    """Tests for the _enrich_notification_with_finding_info function"""

    def test_enriches_with_finding_info(self, mocker):
        mocker.patch(
            "send_notifications.get_security_hub_console_url",
            return_value="https://console.aws.amazon.com/securityhub/finding-link",
        )
        mocker.patch(
            "send_notifications.get_account_alias",
            return_value="my-account-alias",
        )
        notification_event: dict[str, str] = {"accountId": "111111111111"}
        finding_info: FindingInfo = {
            "finding_id": "finding-id-1",
            "finding_description": "test finding",
            "standard_name": "CIS",
            "standard_version": "3.0.0",
            "standard_control": "S3.1",
            "title": "S3 Block Public Access",
            "region": "us-east-1",
            "account": "111111111111",
            "finding_arn": "arn:aws:securityhub:us-east-1:111111111111:finding/test",
        }
        notification_block: Notification = {
            "Message": "Remediation succeeded",
            "State": "SUCCESS",
            "RemediationOutput": "output-text",
            "StepFunctionsExecutionId": "exec-123",
        }

        _enrich_notification_with_finding_info(
            notification_event, finding_info, "finding-id-1", notification_block
        )

        assert notification_event["standardName"] == "CIS"
        assert notification_event["standardVersion"] == "3.0.0"
        assert notification_event["findingDescription"] == "test finding"
        assert (
            notification_event["findingLink"]
            == "https://console.aws.amazon.com/securityhub/finding-link"
        )
        assert notification_event["remediationOutput"] == "output-text"
        assert notification_event["stepFunctionsExecutionId"] == "exec-123"
        assert notification_event["accountAlias"] == "my-account-alias"

    def test_falls_back_to_finding_id_for_link(self, mocker):
        mocker.patch(
            "send_notifications.get_security_hub_console_url",
            return_value="https://console.aws.amazon.com/securityhub/fallback-link",
        )
        mocker.patch(
            "send_notifications.get_account_alias",
            return_value="alias",
        )
        notification_event: dict[str, str] = {"accountId": "111111111111"}

        _enrich_notification_with_finding_info(
            notification_event,
            None,
            "fallback-finding-id",
            {"Message": "", "State": ""},
        )

        assert (
            notification_event["findingLink"]
            == "https://console.aws.amazon.com/securityhub/fallback-link"
        )

    def test_skips_standard_fields_when_finding_info_is_none(self, mocker):
        mocker.patch(
            "send_notifications.get_security_hub_console_url",
            return_value="https://link",
        )
        mocker.patch(
            "send_notifications.get_account_alias",
            return_value="alias",
        )
        notification_event: dict[str, str] = {"accountId": "111111111111"}

        _enrich_notification_with_finding_info(
            notification_event, None, "finding-id", {"Message": "", "State": ""}
        )

        assert "standardName" not in notification_event
        assert "standardVersion" not in notification_event

    def test_handles_alias_lookup_failure(self, mocker):
        from botocore.exceptions import ClientError

        mocker.patch(
            "send_notifications.get_security_hub_console_url",
            return_value="https://link",
        )
        mocker.patch(
            "send_notifications.get_account_alias",
            side_effect=ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "GetAccountAlias",
            ),
        )
        notification_event: dict[str, str] = {"accountId": "111111111111"}

        # Should not raise — logs warning and continues
        _enrich_notification_with_finding_info(
            notification_event,
            {
                "finding_id": "finding-id",
                "finding_description": "test",
                "standard_name": "CIS",
                "standard_version": "1.0",
                "standard_control": "IAM.1",
                "title": "IAM test",
                "region": "us-east-1",
                "account": "111111111111",
                "finding_arn": "arn:test",
            },
            "finding-id",
            {"Message": "", "State": ""},
        )

        assert "accountAlias" not in notification_event


class TestPublishNotificationEvent:
    """Tests for the _publish_notification_event function"""

    def test_publishes_to_sqs_when_queue_url_is_set(self, mocker):
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mock_sqs = mocker.patch("send_notifications._sqs_client")
        mocker.patch(
            "send_notifications.get_security_hub_console_url",
            return_value="https://link",
        )
        mocker.patch(
            "send_notifications.get_account_alias",
            return_value="alias",
        )

        event = _make_event(
            notification={
                "Message": "Remediation succeeded",
                "Details": "",
                "State": "SUCCESS",
            },
            finding={
                "Id": "arn:aws:securityhub:us-east-1:111111111111:finding/test",
                "Compliance": {"SecurityControlId": "S3.1"},
                "Resources": [{"Id": "arn:aws:s3:::bucket", "Type": "AwsS3Bucket"}],
            },
        )
        event["AccountId"] = "111111111111"
        event["Region"] = "us-east-1"
        event["Severity"] = {"Label": "HIGH"}

        _publish_notification_event(event, "SUCCESS")

        mock_sqs.send_message.assert_called_once()
        call_kwargs = mock_sqs.send_message.call_args.kwargs
        assert (
            call_kwargs["QueueUrl"] == "https://sqs.us-east-1.amazonaws.com/123/queue"
        )

        import json

        body = json.loads(call_kwargs["MessageBody"])
        assert body["eventType"] == "remediation"
        assert body["remediationStatus"] == "SUCCESS"
        assert body["controlId"] == "S3.1"

    def test_skips_when_queue_url_is_not_set(self, mocker):
        mocker.patch("send_notifications.NOTIFICATION_QUEUE_URL", None)
        mock_sqs = mocker.patch("send_notifications._sqs_client")

        event = _make_event(notification={"Message": "test", "State": "SUCCESS"})

        _publish_notification_event(event, "SUCCESS")

        mock_sqs.send_message.assert_not_called()

    def test_swallows_exceptions(self, mocker):
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mocker.patch(
            "send_notifications._sqs_client.send_message",
            side_effect=Exception("SQS error"),
        )

        event = _make_event(
            notification={
                "Message": "test",
                "Details": "",
                "State": "FAILED",
            },
            finding={
                "Id": "arn:aws:securityhub:us-east-1:111111111111:finding/test",
                "Compliance": {"SecurityControlId": "S3.1"},
                "Resources": [{"Id": "arn:aws:s3:::bucket", "Type": "AwsS3Bucket"}],
            },
        )
        event["AccountId"] = "111111111111"
        event["Region"] = "us-east-1"
        event["Severity"] = {"Label": "HIGH"}

        # Should not raise
        _publish_notification_event(event, "FAILED")

    def test_enriches_with_finding_info(self, mocker):
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mock_sqs = mocker.patch("send_notifications._sqs_client")
        mocker.patch(
            "send_notifications.get_security_hub_console_url",
            return_value="https://console-link",
        )
        mocker.patch(
            "send_notifications.get_account_alias",
            return_value="my-alias",
        )

        event = _make_event(
            notification={
                "Message": "Remediation succeeded",
                "RemediationOutput": "output-data",
                "StepFunctionsExecutionId": "exec-abc",
                "State": "SUCCESS",
            },
            finding={
                "Id": "arn:aws:securityhub:us-east-1:111111111111:finding/test",
                "Compliance": {"SecurityControlId": "S3.1"},
                "Resources": [{"Id": "arn:aws:s3:::bucket", "Type": "AwsS3Bucket"}],
            },
        )
        event["AccountId"] = "111111111111"
        event["Region"] = "us-east-1"
        event["Severity"] = {"Label": "HIGH"}

        finding_info: FindingInfo = {
            "finding_id": "test-finding",
            "finding_description": "test",
            "standard_name": "AFSBP",
            "standard_version": "1.0.0",
            "standard_control": "S3.1",
            "title": "S3 Block Public Access",
            "region": "us-east-1",
            "account": "111111111111",
            "finding_arn": "arn:aws:securityhub:us-east-1:111111111111:finding/test",
        }

        _publish_notification_event(event, "SUCCESS", finding_info=finding_info)

        mock_sqs.send_message.assert_called_once()
        import json

        body = json.loads(mock_sqs.send_message.call_args.kwargs["MessageBody"])
        assert body["standardName"] == "AFSBP"
        assert body["standardVersion"] == "1.0.0"
        assert body["findingDescription"] == "test"
        assert body["remediationOutput"] == "output-data"
        assert body["stepFunctionsExecutionId"] == "exec-abc"
        assert body["accountAlias"] == "my-alias"


class TestGetFollowupMessage:
    """Tests for the _get_followup_message function."""

    def test_guardduty_returns_followup(self):
        result = _get_followup_message("GuardDuty.IAMUser")
        assert "MANUAL FOLLOW-UP REQUIRED" in result
        assert "CONTAINMENT ACTIONS COMPLETED" in result
        assert "access keys disabled" in result
        assert "REQUIRED NEXT STEPS" in result
        assert "CloudTrail" in result
        assert "Rollback" in result

    def test_macie_returns_followup(self):
        result = _get_followup_message("Macie.SensitiveDataS3Object")
        assert "MANUAL FOLLOW-UP REQUIRED" in result
        assert "PROTECTION ACTIONS COMPLETED" in result
        assert "Block Public Access" in result
        assert "REQUIRED NEXT STEPS" in result
        assert "sensitive data" in result.lower()

    def test_other_control_returns_empty(self):
        assert _get_followup_message("S3.1") == ""
        assert _get_followup_message("IAMAccessAnalyzer.ExternalAccess") == ""
        assert _get_followup_message("Inspector.InstanceVulnerability") == ""
        assert _get_followup_message("") == ""

    def test_guardduty_followup_appended_to_notification_message(self, mocker):
        """Verify build_and_send_notification appends follow-up for GuardDuty."""
        from send_notifications import build_and_send_notification

        mock_notification = mocker.MagicMock()
        event = cast(
            Event,
            {
                "Notification": {
                    "State": "SUCCESS",
                    "Message": "Contained compromised IAM user.",
                    "RemediationOutput": "",
                },
                "ControlId": "GuardDuty.IAMUser",
            },
        )

        mocker.patch("send_notifications.get_account_alias", return_value="test-alias")
        mocker.patch(
            "send_notifications.get_security_hub_console_url",
            return_value="https://link",
        )

        build_and_send_notification(event, mock_notification, "", "", "")

        assigned_message = mock_notification.message
        assert "Contained compromised IAM user." in assigned_message
        assert "MANUAL FOLLOW-UP REQUIRED" in assigned_message
        assert "CONTAINMENT ACTIONS COMPLETED" in assigned_message

    def test_macie_followup_appended_to_notification_message(self, mocker):
        """Verify build_and_send_notification appends follow-up for Macie."""
        from send_notifications import build_and_send_notification

        mock_notification = mocker.MagicMock()
        event = cast(
            Event,
            {
                "Notification": {
                    "State": "SUCCESS",
                    "Message": "Enabled S3 Block Public Access.",
                    "RemediationOutput": "",
                },
                "ControlId": "Macie.SensitiveDataS3Object",
            },
        )

        mocker.patch("send_notifications.get_account_alias", return_value="test-alias")
        mocker.patch(
            "send_notifications.get_security_hub_console_url",
            return_value="https://link",
        )

        build_and_send_notification(event, mock_notification, "", "", "")

        assigned_message = mock_notification.message
        assert "Enabled S3 Block Public Access." in assigned_message
        assert "MANUAL FOLLOW-UP REQUIRED" in assigned_message
        assert "PROTECTION ACTIONS COMPLETED" in assigned_message

    def test_no_followup_for_standard_control(self, mocker):
        """Verify no follow-up is appended for standard controls."""
        from send_notifications import build_and_send_notification

        mock_notification = mocker.MagicMock()
        event = cast(
            Event,
            {
                "Notification": {
                    "State": "SUCCESS",
                    "Message": "Remediation succeeded.",
                    "RemediationOutput": "",
                },
                "ControlId": "S3.1",
            },
        )

        mocker.patch("send_notifications.get_account_alias", return_value="test-alias")
        mocker.patch(
            "send_notifications.get_security_hub_console_url",
            return_value="https://link",
        )

        build_and_send_notification(event, mock_notification, "", "", "")

        assigned_message = mock_notification.message
        assert assigned_message == "Remediation succeeded."


class TestNotificationDispatchResilience:
    """Tests for the finally-block guarantee that SQS and SNS notifications are
    always dispatched regardless of upstream failures.

    These tests mock internal functions (_update_finding_remediation_status,
    update_remediation_status_and_history) rather than system boundaries because:
    - We need to force specific exception propagation paths through lambda_handler's
      try/except/finally structure that cannot be triggered via moto alone
    - The boundary-level integration tests elsewhere in this file already cover the
      happy-path end-to-end; these tests isolate the error-handling control flow
    """

    @mock_aws
    def test_publishes_to_queue_despite_inner_status_update_failure(self, mocker):
        """SQS notification event is published even when update_remediation_status_and_history raises internally."""
        # ARRANGE
        setup_ssm_parameters()
        setup_dynamodb_tables()
        sharr_notification_stub = setup(mocker)

        mocker.patch(
            "send_notifications.update_remediation_status_and_history",
            side_effect=RuntimeError("DDB write failed"),
        )
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mock_sqs = mocker.patch("send_notifications._sqs_client")

        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "FAILED"
        event["Notification"]["Message"] = "Remediation failed"

        # ACT
        lambda_handler(event, {})

        # ASSERT
        mock_sqs.send_message.assert_called_once()
        sharr_notification_stub.notify.assert_called_once()

    @mock_aws
    def test_publishes_to_queue_despite_handler_level_exception(self, mocker):
        """_publish_notification_event runs via finally even when the exception propagates past lambda_handler's try block."""
        # ARRANGE
        setup_ssm_parameters()
        setup_dynamodb_tables()
        sharr_notification_stub = setup(mocker)

        mocker.patch(
            "send_notifications._update_finding_remediation_status",
            side_effect=RuntimeError("status update crashed"),
        )
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mock_sqs = mocker.patch("send_notifications._sqs_client")

        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "FAILED"
        event["Notification"]["Message"] = "Remediation failed"

        # ACT + ASSERT
        with pytest.raises(RuntimeError, match="status update crashed"):
            lambda_handler(event, {})

        mock_sqs.send_message.assert_called_once()
        sharr_notification_stub.notify.assert_called_once()

    @mock_aws
    def test_sends_notification_despite_sqs_publish_failure(self, mocker):
        """build_and_send_notification still runs when SQS send_message raises."""
        # ARRANGE
        setup_ssm_parameters()
        setup_dynamodb_tables()
        sharr_notification_stub = setup(mocker)

        mocker.patch(
            "send_notifications.update_remediation_status_and_history",
        )
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mocker.patch(
            "send_notifications._sqs_client.send_message",
            side_effect=RuntimeError("SQS publish exploded"),
        )

        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "SUCCESS"
        event["Notification"]["Message"] = "Remediation succeeded"
        event["Notification"][
            "StepFunctionsExecutionId"
        ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

        # ACT
        lambda_handler(event, {})

        # ASSERT
        sharr_notification_stub.notify.assert_called_once()

    @mock_aws
    def test_both_legacy_and_new_pipelines_fire_on_happy_path(self, mocker):
        # ARRANGE
        setup_ssm_parameters()
        setup_dynamodb_tables()
        sharr_notification_stub = setup(mocker)
        mocker.patch("send_notifications.update_remediation_status_and_history")
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mock_sqs = mocker.patch("send_notifications._sqs_client")

        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "SUCCESS"
        event["Notification"]["Message"] = "Remediation succeeded"

        # ACT
        lambda_handler(event, {})

        # ASSERT — both pipelines fired exactly once
        mock_sqs.send_message.assert_called_once()
        sharr_notification_stub.notify.assert_called_once()

    @mock_aws
    def test_finding_json_gzipped_on_success(self, mocker):
        """On SUCCESS the history `findingJSON` is a gzip-compressed ASFF
        projection of the finding, regardless of whether the inbound
        `event["Finding"]` is ASFF or OCSF. This restores the documented
        invariant — DynamoDB always stores ASFF — that the rollback /
        IaC-template / reconciliation readers depend on."""
        import gzip
        import json

        setup_ssm_parameters()
        setup_dynamodb_tables()
        setup(mocker)
        mock_update = mocker.patch(
            "send_notifications.update_remediation_status_and_history"
        )
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mocker.patch("send_notifications._sqs_client")

        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "SUCCESS"

        # ACT
        lambda_handler(event, {})

        # ASSERT — synthesized ASFF carries every field the downstream readers
        # (rollback path, IaC rendering, reconciliation) need to function.
        request: RemediationUpdateRequest = mock_update.call_args[0][0]
        assert request.finding_json is not None
        decompressed = json.loads(gzip.decompress(request.finding_json))
        assert decompressed["AwsAccountId"] == event["Finding"]["AwsAccountId"]
        assert decompressed["Id"] == event["Finding"]["Id"]
        assert (
            decompressed["Compliance"]["SecurityControlId"]
            == event["Finding"]["Compliance"]["SecurityControlId"]
        )
        assert (
            decompressed["Resources"][0]["Id"] == event["Finding"]["Resources"][0]["Id"]
        )
        assert (
            decompressed["Resources"][0]["Type"]
            == event["Finding"]["Resources"][0]["Type"]
        )
        # Satisfies _is_asff_finding (Id + AwsAccountId + Resources)
        assert {"Id", "AwsAccountId", "Resources"}.issubset(decompressed.keys())

    @mock_aws
    def test_finding_json_none_on_non_success(self, mocker):
        """On non-SUCCESS statuses, finding_json is not populated."""
        setup_ssm_parameters()
        setup_dynamodb_tables()
        setup(mocker)
        mock_update = mocker.patch(
            "send_notifications.update_remediation_status_and_history"
        )
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mocker.patch("send_notifications._sqs_client")

        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "FAILED"

        # ACT
        lambda_handler(event, {})

        # ASSERT
        request: RemediationUpdateRequest = mock_update.call_args[0][0]
        assert request.finding_json is None

    @mock_aws
    def test_finding_json_normalizes_ocsf_to_asff_for_history(self, mocker):
        """REGRESSION: For multi-service findings ingested via OCSF
        (GuardDuty / Inspector / Macie auto-trigger), the inbound
        ``event["Finding"]`` is OCSF-shaped — it has ``cloud.account.uid``
        instead of ``AwsAccountId`` and ``resources`` instead of ``Resources``.
        Compressing that shape directly broke the rollback path because
        ``findingsService.executeRollback`` reads ``AwsAccountId`` from the
        history blob to construct the Restore execution input. This test
        guarantees the history ``findingJSON`` is a valid ASFF projection
        regardless of the inbound shape, restoring the documented
        "DynamoDB always stores ASFF" invariant.
        """
        import gzip
        import json

        setup_ssm_parameters()
        setup_dynamodb_tables()
        setup(mocker)
        mock_update = mocker.patch(
            "send_notifications.update_remediation_status_and_history"
        )
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mocker.patch("send_notifications._sqs_client")

        # Build an event mirroring what the orchestrator's "Remediation
        # Succeeded" Pass step produces for an OCSF GuardDuty.IAMUser
        # auto-remediation: top-level AccountId / ControlId set by upstream
        # steps, but Finding body still in OCSF native shape.
        ocsf_finding_id = (
            "arn:aws:guardduty:us-east-1:222222222222:detector/abc/finding/xyz"
        )
        ocsf_finding = {
            "finding_info": {
                "uid": ocsf_finding_id,
                "title": "Anomalous API activity from IAM user",
                "desc": "GuardDuty IAMUser anomaly",
            },
            "metadata": {
                "product": {
                    "uid": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
                    "name": "GuardDuty",
                },
            },
            "cloud": {
                "account": {"uid": "222222222222"},
                "region": "us-east-1",
                "provider": "AWS",
            },
            "resources": [
                {
                    "uid": "arn:aws:iam::222222222222:user/compromised",
                    "type": "AwsIamAccessKey",
                    "region": "us-east-1",
                    "account": {"uid": "222222222222"},
                }
            ],
            "severity": "High",
            "severity_id": 4,
        }
        event = {
            "Notification": {
                "State": "SUCCESS",
                "Message": "Contained",
                "RemediationOutput": "",
                "StepFunctionsExecutionId": "arn:aws:states:us-east-1:222222222222:execution:T:e",
            },
            "Finding": ocsf_finding,
            "EventType": "Security Hub Findings - Imported",
            "AccountId": "222222222222",  # populated by upstream orchestrator step
            "Region": "us-east-1",
            "ControlId": "GuardDuty.IAMUser",
            "SecurityStandard": "MultiService",
            "Resources": [],  # upstream Pass step does not set this for OCSF; rely on Finding
        }

        # ACT
        lambda_handler(cast(Event, event), {})

        # ASSERT — the persisted blob is a valid ASFF projection
        request: RemediationUpdateRequest = mock_update.call_args[0][0]
        assert request.finding_json is not None
        decompressed = json.loads(gzip.decompress(request.finding_json))

        # Field-level invariants the rollback / IaC / reconciliation paths require
        assert decompressed["Id"] == ocsf_finding_id
        assert decompressed["AwsAccountId"] == "222222222222"
        assert decompressed["Region"] == "us-east-1"
        assert (
            decompressed["ProductArn"]
            == "arn:aws:securityhub:us-east-1::product/aws/guardduty"
        )
        assert decompressed["Title"] == "Anomalous API activity from IAM user"
        assert decompressed["Severity"]["Label"] == "High"
        assert (
            decompressed["Resources"][0]["Id"]
            == "arn:aws:iam::222222222222:user/compromised"
        )
        assert decompressed["Resources"][0]["Type"] == "AwsIamAccessKey"
        assert decompressed["Resources"][0]["Region"] == "us-east-1"
        assert decompressed["Compliance"]["SecurityControlId"] == "GuardDuty.IAMUser"
        # GeneratorId is required by the Finding validator on the post-
        # remediation Notify path; an empty/missing value raises InvalidFindingJson.
        assert decompressed.get("GeneratorId"), (
            "GeneratorId must be populated so the post-remediation Notify "
            "Lambda's Finding validator does not raise InvalidFindingJson"
        )

        # Shape-level invariants: must satisfy SC_GuardDuty.IAMUser._is_asff_finding
        # (Id + AwsAccountId + Resources) and must NOT carry OCSF-only keys
        # that would confuse the runbook's ASFF dispatch.
        assert {"Id", "AwsAccountId", "Resources"}.issubset(decompressed.keys())
        assert "cloud" not in decompressed
        assert "finding_info" not in decompressed
        assert "resources" not in decompressed

    @mock_aws
    def test_finding_json_preserves_vulnerabilities_for_inspector(self, mocker):
        """REGRESSION: Inspector.InstanceVulnerability runbook patches based on
        Vulnerabilities[0].VulnerablePackages[]. The history-stored ASFF must
        carry that array end-to-end so a rollback / reconciliation re-trigger
        path that reads from the history blob has the data the runbook needs.
        Symmetric with the toAsffShape passthrough in
        normalizedFindingAdapter.ts for the main Findings table.
        """
        import gzip
        import json

        setup_ssm_parameters()
        setup_dynamodb_tables()
        setup(mocker)
        mock_update = mocker.patch(
            "send_notifications.update_remediation_status_and_history"
        )
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mocker.patch("send_notifications._sqs_client")

        inspector_vulnerabilities = [
            {
                "Id": "CVE-2025-14524",
                "FixAvailable": "YES",
                "VulnerablePackages": [
                    {
                        "Name": "curl",
                        "Architecture": "X86_64",
                        "Version": "8.3.0",
                        "FixedInVersion": "0:8.3.0-1.amzn2.0.12",
                    },
                    {
                        "Name": "libcurl",
                        "Architecture": "X86_64",
                        "Version": "8.3.0",
                        "FixedInVersion": "0:8.3.0-1.amzn2.0.12",
                    },
                ],
            }
        ]
        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "SUCCESS"
        event["Finding"]["Vulnerabilities"] = inspector_vulnerabilities

        lambda_handler(event, {})

        request: RemediationUpdateRequest = mock_update.call_args[0][0]
        assert request.finding_json is not None
        decompressed = json.loads(gzip.decompress(request.finding_json))
        assert decompressed.get("Vulnerabilities") == inspector_vulnerabilities

    @mock_aws
    def test_finding_json_translates_ocsf_vulnerabilities_to_asff(self, mocker):
        """OCSF-shaped Inspector findings must round-trip into the history blob
        as ASFF-shaped Vulnerabilities[] — downstream readers expect ASFF."""
        import gzip
        import json

        setup_ssm_parameters()
        setup_dynamodb_tables()
        setup(mocker)
        mock_update = mocker.patch(
            "send_notifications.update_remediation_status_and_history"
        )
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mocker.patch("send_notifications._sqs_client")

        ocsf_vulnerabilities = [
            {
                "cve": {"uid": "CVE-2025-14524"},
                "is_fix_available": True,
                "affected_packages": [
                    {"name": "curl", "architecture": "X86_64", "version": "8.3.0"},
                    {
                        "name": "libcurl",
                        "architecture": "X86_64",
                        "version": "8.3.0",
                    },
                ],
            }
        ]
        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "SUCCESS"
        # OCSF lowercase shape — mirrors what the pre-processor forwards for
        # V2 Vulnerability Detection findings ingested via the OCSF path.
        event["Finding"].pop("Vulnerabilities", None)
        event["Finding"]["vulnerabilities"] = ocsf_vulnerabilities

        lambda_handler(event, {})

        request: RemediationUpdateRequest = mock_update.call_args[0][0]
        assert request.finding_json is not None
        decompressed = json.loads(gzip.decompress(request.finding_json))
        assert decompressed.get("Vulnerabilities") == [
            {
                "Id": "CVE-2025-14524",
                "FixAvailable": "YES",
                "VulnerablePackages": [
                    {"Name": "curl", "Architecture": "X86_64", "Version": "8.3.0"},
                    {
                        "Name": "libcurl",
                        "Architecture": "X86_64",
                        "Version": "8.3.0",
                    },
                ],
            }
        ]

    @mock_aws
    def test_finding_json_omits_vulnerabilities_when_not_present(self, mocker):
        """For non-Inspector findings (or Inspector findings without the
        Vulnerabilities array set on the event), the history blob is unchanged
        — Vulnerabilities is absent rather than serialized as null."""
        import gzip
        import json

        setup_ssm_parameters()
        setup_dynamodb_tables()
        setup(mocker)
        mock_update = mocker.patch(
            "send_notifications.update_remediation_status_and_history"
        )
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mocker.patch("send_notifications._sqs_client")

        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "SUCCESS"
        event["Finding"].pop("Vulnerabilities", None)

        lambda_handler(event, {})

        request: RemediationUpdateRequest = mock_update.call_args[0][0]
        assert request.finding_json is not None
        decompressed = json.loads(gzip.decompress(request.finding_json))
        assert "Vulnerabilities" not in decompressed

    @mock_aws
    def test_severity_fallback_to_critical_on_failure_with_empty_severity(self, mocker):
        """When severity is empty and status is a failure, the notification uses CRITICAL."""
        setup_ssm_parameters()
        setup_dynamodb_tables()
        setup(mocker)
        mocker.patch("send_notifications.update_remediation_status_and_history")
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mock_sqs = mocker.patch("send_notifications._sqs_client")

        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "FAILED"
        # Remove severity so extract_severity returns empty
        event["Finding"].pop("Severity", None)

        # ACT
        lambda_handler(event, {})

        # ASSERT — the SQS message body should contain CRITICAL severity
        call_kwargs = mock_sqs.send_message.call_args[1]
        import json

        body = json.loads(call_kwargs["MessageBody"])
        assert body["severity"] == "CRITICAL"

    @mock_aws
    def test_no_severity_fallback_on_success_with_empty_severity(self, mocker):
        """On SUCCESS, empty severity stays empty (no CRITICAL fallback)."""
        setup_ssm_parameters()
        setup_dynamodb_tables()
        setup(mocker)
        mocker.patch("send_notifications.update_remediation_status_and_history")
        mocker.patch(
            "send_notifications.NOTIFICATION_QUEUE_URL",
            "https://sqs.us-east-1.amazonaws.com/123/queue",
        )
        mock_sqs = mocker.patch("send_notifications._sqs_client")

        event = copy.deepcopy(default_event)
        event["Notification"]["State"] = "SUCCESS"
        event["Finding"].pop("Severity", None)

        # ACT
        lambda_handler(event, {})

        # ASSERT
        call_kwargs = mock_sqs.send_message.call_args[1]
        import json

        body = json.loads(call_kwargs["MessageBody"])
        assert body["severity"] == ""


def test_translate_ocsf_packages_non_list_returns_empty():
    # A non-list (e.g. missing/malformed affected_packages) yields an empty list.
    assert _translate_ocsf_packages(None) == []
    assert _translate_ocsf_packages("not-a-list") == []


def test_translate_ocsf_packages_skips_non_dict_and_maps_fields():
    packages = [
        {"name": "openssl", "architecture": "x86_64", "version": "1.1.1"},
        "not-a-dict",
    ]
    assert _translate_ocsf_packages(packages) == [
        {"Name": "openssl", "Architecture": "x86_64", "Version": "1.1.1"}
    ]
