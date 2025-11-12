# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import copy
import os
from datetime import datetime, timedelta
from typing import cast

import boto3
import pytest
from moto import mock_aws
from send_notifications import (
    Event,
    RemediationUpdateRequest,
    _extract_security_control_id,
    _is_notified_workflow,
    _is_resolved_item,
    calculate_history_ttl_timestamp,
    create_and_send_cloudwatch_metrics,
    get_control_id_from_finding_id,
    get_finding_type,
    lambda_handler,
    map_remediation_status,
    sanitize_control_id,
    set_message_prefix_and_suffix,
    update_remediation_status_and_history,
)

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
    dynamodb = boto3.client("dynamodb", region_name="us-east-1")

    # Create findings table
    dynamodb.create_table(
        TableName="test-findings-table",
        KeySchema=[
            {"AttributeName": "findingType", "KeyType": "HASH"},
            {"AttributeName": "findingId", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "findingType", "AttributeType": "S"},
            {"AttributeName": "findingId", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    # Create history table
    dynamodb.create_table(
        TableName="test-history-table",
        KeySchema=[
            {"AttributeName": "findingType", "KeyType": "HASH"},
            {"AttributeName": "findingId#executionId", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "findingType", "AttributeType": "S"},
            {"AttributeName": "findingId#executionId", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    os.environ["FINDINGS_TABLE_NAME"] = "test-findings-table"
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"


def setup(mocker):
    sharr_notification_stub = mocker.stub()
    sharr_notification_stub.notify = mocker.Mock()
    mocker.patch(
        "send_notifications.sechub_findings.ASRNotification",
        return_value=sharr_notification_stub,
    )
    mocker.patch("send_notifications.CloudWatchMetrics.send_metric", return_value=None)
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
    event["GenerateTicket"] = {"Ok": False, "ResponseReason": "There was an error"}
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
def test_send_operational_metrics_with_event_type(mocker):
    # ARRANGE
    setup_ssm_parameters()
    setup_dynamodb_tables()

    mock_urlopen = mocker.patch("layer.metrics.urlopen")
    sharr_notification_stub = setup(mocker)

    event = cast(Event, copy.deepcopy(default_event))
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

    event = cast(Event, copy.deepcopy(default_event))
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


def test_calculate_history_ttl_timestamp():

    timestamp = "2024-01-01T00:00:00Z"
    ttl = calculate_history_ttl_timestamp(timestamp)

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
        "send_notifications._try_update_with_existing_history", return_value=True
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
        "send_notifications._try_update_with_existing_history", return_value=False
    )
    mocker.patch("send_notifications._create_history_with_finding_update")

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

    event = cast(Event, copy.deepcopy(default_event))
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

    event = cast(Event, copy.deepcopy(default_event))
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
def test_update_finding_remediation_status_missing_finding_type(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )
    setup(mocker)

    event = cast(Event, copy.deepcopy(default_event))
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    event["Finding"][
        "Id"
    ] = "arn:aws:securityhub:us-east-1:123456789012:finding/custom-format/test-id"
    if "Compliance" in event["Finding"]:
        del event["Finding"]["Compliance"]["SecurityControlId"]

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
    event_with_compliance = cast(
        Event,
        {
            "Finding": {
                "Compliance": {"SecurityControlId": "S3.13"},
                "ProductFields": {"ControlId": "S3.14"},
            }
        },
    )
    result = _extract_security_control_id(event_with_compliance)
    assert result == "S3.13"

    event_with_fallback = cast(
        Event,
        {
            "Finding": {
                "Compliance": {"SecurityControlId": ""},
                "ProductFields": {"ControlId": "S3.14"},
            }
        },
    )
    result = _extract_security_control_id(event_with_fallback)
    assert result == "S3.14"

    event_no_finding: Event = cast(Event, {})
    result = _extract_security_control_id(event_no_finding)
    assert result == ""


def test_get_finding_type_comprehensive():
    event_with_finding_id = cast(
        Event,
        {
            "Finding": {
                "Id": "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.15/finding/abc123",
                "Compliance": {"SecurityControlId": "S3.13"},
                "ProductFields": {"ControlId": "S3.14"},
            }
        },
    )
    result = get_finding_type(event_with_finding_id)
    assert result == "security-control/S3.15"

    event_compliance_fallback = cast(
        Event,
        {
            "Finding": {
                "Id": "invalid-finding-id",
                "Compliance": {"SecurityControlId": "S3.13"},
                "ProductFields": {"ControlId": "S3.14"},
            }
        },
    )
    result = get_finding_type(event_compliance_fallback)
    assert result == "S3.13"

    event_product_fields_fallback = cast(
        Event,
        {
            "Finding": {
                "Id": "invalid-finding-id",
                "Compliance": {"SecurityControlId": ""},
                "ProductFields": {"ControlId": "S3.14"},
            }
        },
    )
    result = get_finding_type(event_product_fields_fallback)
    assert result == "S3.14"

    event_no_control_id = cast(
        Event,
        {
            "Finding": {
                "Id": "invalid-finding-id",
                "Compliance": {},
                "ProductFields": {},
            }
        },
    )
    result = get_finding_type(event_no_control_id)
    assert result == ""


def test_is_notified_workflow():
    # Test NOTIFIED workflow with regular event type
    notified_event = cast(
        Event,
        {
            "Finding": {
                "Workflow": {"Status": "NOTIFIED"},
                "Id": "test-finding-id",
            },
            "EventType": "Security Hub Findings - Imported",
        },
    )
    assert _is_notified_workflow(notified_event) is True

    # Test NOTIFIED workflow with Custom Action event type - should return False
    notified_custom_action_event = cast(
        Event,
        {
            "Finding": {
                "Workflow": {"Status": "NOTIFIED"},
                "Id": "test-finding-id",
            },
            "EventType": "Security Hub Findings - Custom Action",
        },
    )
    assert _is_notified_workflow(notified_custom_action_event) is False

    # Test NOTIFIED workflow with API Action event type - should return False
    notified_api_action_event = cast(
        Event,
        {
            "Finding": {
                "Workflow": {"Status": "NOTIFIED"},
                "Id": "test-finding-id",
            },
            "EventType": "Security Hub Findings - API Action",
        },
    )
    assert _is_notified_workflow(notified_api_action_event) is False

    # Test NOTIFIED workflow without EventType - should return True
    notified_no_event_type = cast(
        Event,
        {
            "Finding": {
                "Workflow": {"Status": "NOTIFIED"},
                "Id": "test-finding-id",
            }
        },
    )
    assert _is_notified_workflow(notified_no_event_type) is True

    # Test non-NOTIFIED workflow
    new_event = cast(
        Event,
        {
            "Finding": {
                "Workflow": {"Status": "NEW"},
                "Id": "test-finding-id",
            }
        },
    )
    assert _is_notified_workflow(new_event) is False

    # Test missing workflow
    no_workflow_event = cast(
        Event,
        {
            "Finding": {
                "Id": "test-finding-id",
            }
        },
    )
    assert _is_notified_workflow(no_workflow_event) is False

    # Test empty workflow
    empty_workflow_event = cast(
        Event,
        {
            "Finding": {
                "Workflow": {},
                "Id": "test-finding-id",
            }
        },
    )
    assert _is_notified_workflow(empty_workflow_event) is False

    # Test no finding
    no_finding_event = cast(Event, {})
    assert _is_notified_workflow(no_finding_event) is False

    # Test workflow is not a dict
    invalid_workflow_event = cast(
        Event,
        {
            "Finding": {
                "Workflow": "NOTIFIED",  # String instead of dict
                "Id": "test-finding-id",
            }
        },
    )
    assert _is_notified_workflow(invalid_workflow_event) is False


@mock_aws
def test_lambda_handler_with_product_fields_fallback(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    sharr_notification_stub = setup(mocker)
    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )

    event = cast(Event, copy.deepcopy(default_event))
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

    event = cast(Event, copy.deepcopy(default_event))
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

    event = cast(Event, copy.deepcopy(default_event))
    event["Finding"]["Workflow"] = {"Status": "NEW"}  # Set non-NOTIFIED workflow status
    event["Notification"][
        "StepFunctionsExecutionId"
    ] = "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution-id"

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1

    mock_update.assert_called_once()


def test_security_hub_v2_enabled_finding_link(mocker):
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"
    event = default_event
    sharr_notification_stub = setup(mocker)

    lambda_handler(event, {})

    assert sharr_notification_stub.notify.call_count == 1
    assert (
        sharr_notification_stub.finding_link
        == "https://console.aws.amazon.com/securityhub/v2/home?region=us-east-1#/findings?search=finding_info.uid%3D%255Coperator%255C%253AEQUALS%255C%253Aarn%3Aaws%3Asecurityhub%3Aus-east-1%3A111111111111%3Asubscription%2Fcis-aws-foundations-benchmark%2Fv%2F3.0.0%2Ffoobar.1%2Ffinding%2Fc605d623-ee6b-460d-9deb-0e8c0551d155"
    )

    # Clean up
    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_should_override_to_success_with_not_new_and_resolved():
    event = cast(
        Event,
        {
            "Notification": {
                "State": "NOT_NEW",
                "Message": "Finding Workflow State is not NEW (RESOLVED).",
            },
            "Finding": {
                "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/test/finding/123",
                "Workflow": {"Status": "RESOLVED"},
            },
        },
    )

    result = _is_resolved_item(event)

    assert result is True


def test_should_override_to_success_with_different_state():
    event = cast(
        Event,
        {
            "Notification": {
                "State": "QUEUED",
                "Message": "Remediation queued",
            },
            "Finding": {
                "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/test/finding/123",
                "Workflow": {"Status": "RESOLVED"},
            },
        },
    )

    result = _is_resolved_item(event)

    assert result is False


def test_should_override_to_success_with_different_workflow_status():
    event = cast(
        Event,
        {
            "Notification": {
                "State": "NOT_NEW",
                "Message": "Finding Workflow State is not NEW (NOTIFIED).",
            },
            "Finding": {
                "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/test/finding/123",
                "Workflow": {"Status": "NOTIFIED"},
            },
        },
    )

    result = _is_resolved_item(event)

    assert result is False


def test_should_override_to_success_without_finding():
    event = cast(
        Event,
        {
            "Notification": {
                "State": "NOT_NEW",
                "Message": "Test message",
            },
        },
    )

    result = _is_resolved_item(event)

    assert result is False


@mock_aws
def test_lambda_handler_overrides_status_for_resolved_workflow(mocker):
    setup_ssm_parameters()
    setup_dynamodb_tables()

    sharr_notification_stub = setup(mocker)
    mock_update = mocker.patch(
        "send_notifications.update_remediation_status_and_history"
    )

    event = cast(Event, copy.deepcopy(default_event))
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


def test_extract_finding_fields():
    from send_notifications import _extract_finding_fields

    item = {
        "accountId": {"S": "123456789012"},
        "resourceId": {"S": "i-1234567890abcdef0"},
        "resourceType": {"S": "AwsEc2Instance"},
        "resourceTypeNormalized": {"S": "EC2Instance"},
        "severity": {"S": "HIGH"},
        "region": {"S": "us-east-1"},
        "lastUpdatedBy": {"S": "Automated"},
    }

    result = _extract_finding_fields(item)

    assert result["accountId"] == "123456789012"
    assert result["resourceId"] == "i-1234567890abcdef0"
    assert result["resourceType"] == "AwsEc2Instance"
    assert result["resourceTypeNormalized"] == "EC2Instance"
    assert result["severity"] == "HIGH"
    assert result["region"] == "us-east-1"
    assert result["lastUpdatedBy"] == "Automated"


def test_extract_finding_fields_partial():
    from send_notifications import _extract_finding_fields

    item = {
        "accountId": {"S": "123456789012"},
        "severity": {"S": "MEDIUM"},
    }

    result = _extract_finding_fields(item)

    assert result["accountId"] == "123456789012"
    assert result["severity"] == "MEDIUM"
    assert "resourceId" not in result
    assert "resourceType" not in result


def test_extract_finding_fields_empty():
    from typing import Any

    from send_notifications import _extract_finding_fields

    item: dict[str, Any] = {}
    result = _extract_finding_fields(item)

    assert result == {}


def test_merge_finding_data_into_item():
    from send_notifications import FindingData, _merge_finding_data_into_item

    item = {
        "findingId": {"S": "test-finding-id"},
        "accountId": {"S": "original-account"},
    }

    finding_data: FindingData = {
        "accountId": "123456789012",
        "resourceId": "i-1234567890abcdef0",
        "resourceType": "AwsEc2Instance",
        "severity": "HIGH",
        "region": "us-west-2",
    }

    _merge_finding_data_into_item(item, finding_data)

    # Should override existing accountId
    assert item["accountId"] == {"S": "123456789012"}
    # Should add new fields
    assert item["resourceId"] == {"S": "i-1234567890abcdef0"}
    assert item["resourceType"] == {"S": "AwsEc2Instance"}
    assert item["severity"] == {"S": "HIGH"}
    assert item["region"] == {"S": "us-west-2"}
    # Should preserve original fields
    assert item["findingId"] == {"S": "test-finding-id"}


def test_merge_finding_data_into_item_partial():
    from send_notifications import FindingData, _merge_finding_data_into_item

    item = {"findingId": {"S": "test-finding-id"}}

    finding_data: FindingData = {
        "accountId": "123456789012",
        "severity": "LOW",
    }

    _merge_finding_data_into_item(item, finding_data)

    assert item["accountId"] == {"S": "123456789012"}
    assert item["severity"] == {"S": "LOW"}
    assert "resourceId" not in item


def test_parse_orchestrator_input_valid_json():
    """Test _parse_orchestrator_input with valid JSON."""
    from send_notifications import _parse_orchestrator_input

    input_str = '{"detail": {"findings": [{"Id": "test-id"}]}}'
    result = _parse_orchestrator_input(input_str)

    assert result == {"detail": {"findings": [{"Id": "test-id"}]}}


def test_parse_orchestrator_input_invalid_json():
    from send_notifications import _parse_orchestrator_input

    input_str = "invalid json {{"
    result = _parse_orchestrator_input(input_str)

    assert result == {}


def test_parse_orchestrator_input_empty_string():
    from send_notifications import _parse_orchestrator_input

    input_str = ""
    result = _parse_orchestrator_input(input_str)

    assert result == {}


def test_add_optional_finding_fields():
    from send_notifications import Event, _add_optional_finding_fields

    transformed_event: Event = {
        "Notification": {
            "Message": "test",
            "State": "SUCCESS",
        },
        "Finding": {"Id": "test-id"},
    }

    finding_data = {
        "AwsAccountId": "123456789012",
        "Region": "us-east-1",
        "Resources": [{"Id": "i-123", "Type": "AwsEc2Instance"}],
        "Severity": {"Label": "HIGH"},
        "ProductFields": {"StandardsGuideArn": "arn:aws:securityhub:::ruleset/cis"},
        "Compliance": {"SecurityControlId": "EC2.1"},
    }

    _add_optional_finding_fields(transformed_event, finding_data)

    assert transformed_event["AccountId"] == "123456789012"
    assert transformed_event["Region"] == "us-east-1"
    assert transformed_event["Resources"] == [{"Id": "i-123", "Type": "AwsEc2Instance"}]
    assert transformed_event["Severity"] == {"Label": "HIGH"}
    assert transformed_event["SecurityStandard"] == "arn:aws:securityhub:::ruleset/cis"
    assert transformed_event["ControlId"] == "EC2.1"


def test_add_optional_finding_fields_partial():
    """Test _add_optional_finding_fields with partial data."""
    from send_notifications import Event, _add_optional_finding_fields

    transformed_event: Event = {
        "Notification": {
            "Message": "test",
            "State": "SUCCESS",
        },
        "Finding": {"Id": "test-id"},
    }

    finding_data = {
        "AwsAccountId": "123456789012",
        "Region": "us-west-2",
    }

    _add_optional_finding_fields(transformed_event, finding_data)

    assert transformed_event["AccountId"] == "123456789012"
    assert transformed_event["Region"] == "us-west-2"
    assert "Resources" not in transformed_event
    assert "Severity" not in transformed_event
    assert "SecurityStandard" not in transformed_event
    assert "ControlId" not in transformed_event


def test_add_optional_finding_fields_nested_missing():
    """Test _add_optional_finding_fields when nested fields are missing."""
    from send_notifications import Event, _add_optional_finding_fields

    transformed_event: Event = {
        "Notification": {
            "Message": "test",
            "State": "SUCCESS",
        },
        "Finding": {"Id": "test-id"},
    }

    finding_data = {
        "AwsAccountId": "123456789012",
        "ProductFields": {},  # Empty ProductFields
        "Compliance": {},  # Empty Compliance
    }

    _add_optional_finding_fields(transformed_event, finding_data)

    assert transformed_event["AccountId"] == "123456789012"
    assert "SecurityStandard" not in transformed_event
    assert "ControlId" not in transformed_event


def test_transform_stepfunctions_failure_event_complete():
    from send_notifications import _transform_stepfunctions_failure_event

    raw_event = {
        "detail": {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution",
            "name": "test-execution",
            "status": "FAILED",
            "cause": "Lambda function failed",
            "error": "LambdaError",
            "input": '{"detail": {"findings": [{"Id": "test-finding-id", "AwsAccountId": "123456789012", "Region": "us-east-1"}], "actionName": "CustomAction"}, "detail-type": "Custom Action"}',
        }
    }

    result = _transform_stepfunctions_failure_event(raw_event)

    assert result["Notification"]["State"] == "FAILED"
    assert "test-execution" in result["Notification"]["Message"]
    assert "LambdaError" in result["Notification"]["Details"]
    assert "Lambda function failed" in result["Notification"]["Details"]
    assert (
        result["Notification"]["StepFunctionsExecutionId"]
        == "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution"
    )
    assert result["Finding"]["Id"] == "test-finding-id"
    assert result["AccountId"] == "123456789012"
    assert result["Region"] == "us-east-1"
    assert result["CustomActionName"] == "CustomAction"
    assert result["EventType"] == "Custom Action"


def test_transform_stepfunctions_failure_event_minimal():
    from send_notifications import _transform_stepfunctions_failure_event

    raw_event = {
        "detail": {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution",
            "status": "TIMEOUT",
        }
    }

    result = _transform_stepfunctions_failure_event(raw_event)

    assert result["Notification"]["State"] == "TIMEOUT"
    assert result["Finding"]["Id"] == "unknown"
    assert result["Finding"]["Title"] == "Step Functions Execution Failure"


def test_transform_stepfunctions_failure_event_invalid_json():
    from send_notifications import _transform_stepfunctions_failure_event

    raw_event = {
        "detail": {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution",
            "status": "FAILED",
            "input": "invalid json {{",
        }
    }

    result = _transform_stepfunctions_failure_event(raw_event)

    assert result["Notification"]["State"] == "FAILED"
    assert result["Finding"]["Id"] == "unknown"


def test_transform_stepfunctions_failure_event_exception(mocker):
    from send_notifications import _transform_stepfunctions_failure_event

    # Mock logger to avoid exc_info conflict
    mocker.patch("send_notifications.logger.error")

    # Pass None to trigger exception
    raw_event = None

    result = _transform_stepfunctions_failure_event(raw_event)  # type: ignore[arg-type]

    assert result["Notification"]["State"] == "FAILED"
    assert "Failed to transform" in result["Notification"]["Message"]
    assert result["Finding"]["Id"] == "unknown"
    assert result["EventType"] == "Error"


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
