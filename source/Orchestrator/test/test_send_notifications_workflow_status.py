# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that a failure notification only flags findings whose workflow status was NEW."""
import json
from collections.abc import Iterator
from typing import Any, Literal, TypedDict

import boto3
import pytest
from botocore.model import OperationModel
from botocore.stub import Stubber
from layer import sechub_findings
from layer.event_transformers import Event
from layer.sechub_findings import WorkflowStatus
from layer.test.conftest import create_dynamodb_tables
from moto import mock_aws
from pytest_mock import MockerFixture
from send_notifications import lambda_handler

ASFF_FINDING_ID = (
    "arn:aws:securityhub:us-east-1:111111111111:security-control/S3.1/finding/"
    "c605d623-ee6b-460d-9deb-0e8c0551d155"
)
OCSF_FINDING_ID = "arn:aws:inspector2:us-east-1:111111111111:finding/abc123"
EXECUTION_ID = "arn:aws:states:us-east-1:111111111111:execution:TestSM:test-exec"
CUSTOM_ACTION_EVENT_TYPE = "Security Hub Findings - Custom Action"


class SecurityHubRequest(TypedDict):
    operation: str
    params: dict[str, Any]


class SecurityHubRecorder(TypedDict):
    requests: list[SecurityHubRequest]
    stubber: Stubber


class NotificationEnvironment(TypedDict):
    sqs_queue_url: str
    securityhub: SecurityHubRecorder


def _asff_event(
    *,
    state: Literal["NOT_NEW", "FAILED"],
    message: str,
    workflow_status: WorkflowStatus,
    event_type: str | None = None,
) -> Event:
    event: Event = {
        "Notification": {
            "State": state,
            "Message": message,
            "StepFunctionsExecutionId": EXECUTION_ID,
        },
        "Finding": {
            "Id": ASFF_FINDING_ID,
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "security-control/S3.1",
            "AwsAccountId": "111111111111",
            "Compliance": {"SecurityControlId": "S3.1"},
            "ProductFields": {},
            "Resources": [
                {
                    "Type": "AwsS3Bucket",
                    "Id": "arn:aws:s3:::test-bucket",
                    "Region": "us-east-1",
                }
            ],
            "Title": "S3.1 test finding",
            "Description": "test description",
            "Workflow": {"Status": workflow_status},
        },
    }
    if event_type is not None:
        event["EventType"] = event_type
    return event


def _ocsf_event(*, status_id: int) -> Event:
    return {
        "Notification": {
            "State": "FAILED",
            "Message": "Remediation failed",
            "StepFunctionsExecutionId": EXECUTION_ID,
        },
        "Finding": {
            "class_name": "Vulnerability Finding",
            "finding_info": {"uid": OCSF_FINDING_ID, "title": "t", "desc": "d"},
            "metadata": {
                "product": {
                    "uid": "arn:aws:securityhub:us-east-1::productv2/aws/inspector"
                }
            },
            "cloud": {"account": {"uid": "111111111111"}},
            "resources": [{"uid": "i-0123456789abcdef0", "region": "us-east-1"}],
            "status_id": status_id,
        },
        "ControlId": "Inspector.InstanceVulnerability",
    }


def _record_securityhub_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> SecurityHubRecorder:
    """Route the layer's Security Hub client through a Stubber, recording every request.

    moto does not implement BatchUpdateFindings or BatchUpdateFindingsV2, so a Stubber stands in for it.
    """
    client = boto3.client("securityhub", region_name="us-east-1")
    requests: list[SecurityHubRequest] = []

    def record_request(
        params: dict[str, Any], model: OperationModel, **_: object
    ) -> None:
        requests.append({"operation": model.name, "params": params})

    # This event fires before the Stubber's hooks, so a request is recorded even when the Stubber rejects it.
    client.meta.events.register("provide-client-params.securityhub", record_request)
    stubber = Stubber(client)
    stubber.activate()
    monkeypatch.setattr(sechub_findings, "securityhub", client)
    return {"requests": requests, "stubber": stubber}


def _expect_flag_responses(stubber: Stubber) -> None:
    stubber.add_response(
        "batch_update_findings_v2",
        {"ProcessedFindings": [], "UnprocessedFindings": []},
    )
    stubber.add_response(
        "batch_update_findings",
        {"ProcessedFindings": [], "UnprocessedFindings": []},
    )


def _received_sns_notifications(sqs_queue_url: str) -> list[dict[str, Any]]:
    messages = boto3.client("sqs", region_name="us-east-1").receive_message(
        QueueUrl=sqs_queue_url, MaxNumberOfMessages=10
    )
    return [
        json.loads(json.loads(message["Body"])["Message"])
        for message in messages.get("Messages", [])
    ]


@pytest.fixture
def notification_environment(
    mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
) -> Iterator[NotificationEnvironment]:
    monkeypatch.setenv("SECURITY_HUB_V2_ENABLED", "true")
    monkeypatch.setenv("FINDINGS_TABLE_NAME", "test-findings-table")
    monkeypatch.setenv("HISTORY_TABLE_NAME", "test-history-table")
    with mock_aws():
        ssm = boto3.client("ssm", region_name="us-east-1")
        ssm.put_parameter(
            Name="/Solutions/SO0111/version", Value="v1.0.0", Type="String"
        )
        create_dynamodb_tables()

        sqs = boto3.client("sqs", region_name="us-east-1")
        sqs_queue_url = sqs.create_queue(QueueName="asr-notifications")["QueueUrl"]
        sqs_queue_arn = sqs.get_queue_attributes(
            QueueUrl=sqs_queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        sns = boto3.client("sns", region_name="us-east-1")
        topic_arn = sns.create_topic(Name="SO0111-ASR_Topic")["TopicArn"]
        sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=sqs_queue_arn)

        # Operational metrics post to an external endpoint and are not under test here.
        mocker.patch("send_notifications.Metrics.send_metrics", return_value=None)

        yield {
            "sqs_queue_url": sqs_queue_url,
            "securityhub": _record_securityhub_requests(monkeypatch),
        }


@pytest.mark.parametrize("workflow_status", ["SUPPRESSED", "RESOLVED", "NOTIFIED"])
def test_not_new_finding_gets_no_security_hub_write(
    notification_environment: NotificationEnvironment, workflow_status: WorkflowStatus
) -> None:
    # ARRANGE
    event = _asff_event(
        state="NOT_NEW",
        message=f"Finding Workflow State is not NEW ({workflow_status}).",
        workflow_status=workflow_status,
    )

    # ACT
    lambda_handler(event, {})

    # ASSERT
    assert notification_environment["securityhub"]["requests"] == []
    sns_notifications = _received_sns_notifications(
        notification_environment["sqs_queue_url"]
    )
    assert [
        notification["Remediation_Status"] for notification in sns_notifications
    ] == ["NOT_NEW"]
    assert sns_notifications[0]["Severity"] == "ERROR"


@pytest.mark.parametrize("workflow_status", ["SUPPRESSED", "RESOLVED", "NOTIFIED"])
def test_failed_manual_remediation_on_non_new_finding_gets_no_security_hub_write(
    notification_environment: NotificationEnvironment, workflow_status: WorkflowStatus
) -> None:
    # ARRANGE
    event = _asff_event(
        state="FAILED",
        message="Remediation failed",
        workflow_status=workflow_status,
        event_type=CUSTOM_ACTION_EVENT_TYPE,
    )

    # ACT
    lambda_handler(event, {})

    # ASSERT
    assert notification_environment["securityhub"]["requests"] == []
    sns_notifications = _received_sns_notifications(
        notification_environment["sqs_queue_url"]
    )
    assert [notification["Severity"] for notification in sns_notifications] == ["ERROR"]


@pytest.mark.parametrize("event_type", [None, CUSTOM_ACTION_EVENT_TYPE])
def test_failed_remediation_on_new_asff_finding_flags_it(
    notification_environment: NotificationEnvironment, event_type: str | None
) -> None:
    # ARRANGE
    securityhub = notification_environment["securityhub"]
    _expect_flag_responses(securityhub["stubber"])
    event = _asff_event(
        state="FAILED",
        message="Remediation failed",
        workflow_status="NEW",
        event_type=event_type,
    )

    # ACT
    lambda_handler(event, {})

    # ASSERT
    securityhub["stubber"].assert_no_pending_responses()
    writes = {
        request["operation"]: request["params"] for request in securityhub["requests"]
    }
    assert writes["BatchUpdateFindingsV2"]["StatusId"] == 2
    assert writes["BatchUpdateFindingsV2"]["Comment"] == "Remediation failed"
    assert writes["BatchUpdateFindings"]["Workflow"] == {"Status": "NOTIFIED"}
    assert writes["BatchUpdateFindings"]["Note"]["Text"] == "Remediation failed"


def test_failed_remediation_on_new_ocsf_finding_flags_it(
    notification_environment: NotificationEnvironment,
) -> None:
    # ARRANGE
    securityhub = notification_environment["securityhub"]
    _expect_flag_responses(securityhub["stubber"])

    # ACT
    lambda_handler(_ocsf_event(status_id=1), {})

    # ASSERT
    securityhub["stubber"].assert_no_pending_responses()
    writes = {
        request["operation"]: request["params"] for request in securityhub["requests"]
    }
    assert writes["BatchUpdateFindingsV2"]["StatusId"] == 2
    identifiers = writes["BatchUpdateFindingsV2"]["FindingIdentifiers"]
    assert identifiers[0]["FindingInfoUid"] == OCSF_FINDING_ID


@pytest.mark.parametrize("status_id", [2, 3, 4])
def test_failed_remediation_on_non_new_ocsf_finding_gets_no_security_hub_write(
    notification_environment: NotificationEnvironment, status_id: int
) -> None:
    # ARRANGE
    event = _ocsf_event(status_id=status_id)

    # ACT
    lambda_handler(event, {})

    # ASSERT
    assert notification_environment["securityhub"]["requests"] == []
