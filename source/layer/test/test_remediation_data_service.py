# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os

from layer.history_repository import RemediationUpdateRequest
from layer.remediation_data_service import (
    get_console_host,
    get_security_hub_console_url,
    map_remediation_status,
    update_remediation_status_and_history,
)
from moto import mock_aws

from .conftest import create_dynamodb_tables


def test_get_console_host():
    # ACT & ASSERT
    assert get_console_host("aws") == "console.aws.amazon.com"
    assert get_console_host("aws-us-gov") == "console.amazonaws-us-gov.com"
    assert get_console_host("aws-cn") == "console.amazonaws.cn"
    assert get_console_host("unknown") == "console.aws.amazon.com"


def test_get_security_hub_console_url_default():
    # ARRANGE
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["AWS_PARTITION"] = "aws"
    os.environ.pop("SECURITY_HUB_V2_ENABLED", None)

    # ACT
    result = get_security_hub_console_url("test-finding-id")

    # ASSERT
    assert "console.aws.amazon.com" in result
    assert "us-east-1" in result
    assert "test-finding-id" in result
    assert "/securityhub/home" in result


def test_get_security_hub_console_url_v2_enabled():
    # ARRANGE
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"
    os.environ["AWS_REGION"] = "us-west-2"
    os.environ["AWS_PARTITION"] = "aws"

    # ACT
    result = get_security_hub_console_url("test-finding-id")

    # ASSERT
    assert "console.aws.amazon.com" in result
    assert "us-west-2" in result
    assert "/securityhub/v2/home" in result

    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_map_remediation_status():
    # ACT & ASSERT
    assert map_remediation_status("SUCCESS") == "SUCCESS"
    assert map_remediation_status("success") == "SUCCESS"
    assert map_remediation_status("NOT_STARTED") == "NOT_STARTED"
    assert map_remediation_status(None) == "NOT_STARTED"
    assert map_remediation_status("") == "NOT_STARTED"
    assert map_remediation_status("QUEUED") == "IN_PROGRESS"
    assert map_remediation_status("RUNNING") == "IN_PROGRESS"
    assert map_remediation_status("IN_PROGRESS") == "IN_PROGRESS"
    assert map_remediation_status("FAILED") == "FAILED"
    assert map_remediation_status("LAMBDA_ERROR") == "FAILED"
    assert map_remediation_status("UNKNOWN_STATUS") == "FAILED"
    # Rollback lifecycle states are preserved (case-insensitive) so each rollback
    # outcome stays distinct from SUCCESS/FAILED.
    assert map_remediation_status("ROLLBACK_IN_PROGRESS") == "ROLLBACK_IN_PROGRESS"
    assert map_remediation_status("rollback_in_progress") == "ROLLBACK_IN_PROGRESS"
    assert map_remediation_status("ROLLBACK_SUCCESS") == "ROLLBACK_SUCCESS"
    assert map_remediation_status("ROLLBACK_FAILED") == "ROLLBACK_FAILED"


@mock_aws
def test_update_remediation_status_and_history_success(mocker):
    # ARRANGE
    dynamodb = create_dynamodb_tables()

    dynamodb.put_item(
        TableName="test-findings-table",
        Item={
            "findingType": {"S": "EC2.1"},
            "findingId": {"S": "test-finding-id"},
            "remediationStatus": {"S": "IN_PROGRESS"},
        },
    )

    dynamodb.put_item(
        TableName="test-history-table",
        Item={
            "findingType": {"S": "EC2.1"},
            "findingId#executionId": {"S": "test-finding-id#exec-123"},
            "remediationStatus": {"S": "IN_PROGRESS"},
        },
    )

    os.environ["FINDINGS_TABLE_NAME"] = "test-findings-table"
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"
    os.environ["AWS_REGION"] = "us-east-1"

    mocker.patch(
        "layer.remediation_data_service.AWSCachedClient"
    ).return_value.get_connection.return_value = dynamodb

    request = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="exec-123",
        remediation_status="SUCCESS",
        finding_type="EC2.1",
    )

    # ACT
    update_remediation_status_and_history(request)

    # ASSERT
    finding_response = dynamodb.get_item(
        TableName="test-findings-table",
        Key={"findingType": {"S": "EC2.1"}, "findingId": {"S": "test-finding-id"}},
    )
    assert finding_response["Item"]["remediationStatus"]["S"] == "SUCCESS"

    history_response = dynamodb.get_item(
        TableName="test-history-table",
        Key={
            "findingType": {"S": "EC2.1"},
            "findingId#executionId": {"S": "test-finding-id#exec-123"},
        },
    )
    assert history_response["Item"]["remediationStatus"]["S"] == "SUCCESS"

    del os.environ["FINDINGS_TABLE_NAME"]
    del os.environ["HISTORY_TABLE_NAME"]
    del os.environ["AWS_REGION"]


@mock_aws
def test_update_remediation_status_and_history_fallback_to_create(mocker):
    # ARRANGE
    dynamodb = create_dynamodb_tables()

    dynamodb.put_item(
        TableName="test-findings-table",
        Item={
            "findingType": {"S": "S3.1"},
            "findingId": {"S": "new-finding-id"},
            "accountId": {"S": "123456789012"},
            "resourceId": {"S": "bucket-name"},
            "severity": {"S": "HIGH"},
        },
    )

    os.environ["FINDINGS_TABLE_NAME"] = "test-findings-table"
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["HISTORY_TTL_DAYS"] = "365"

    mocker.patch(
        "layer.remediation_data_service.AWSCachedClient"
    ).return_value.get_connection.return_value = dynamodb

    request = RemediationUpdateRequest(
        finding_id="new-finding-id",
        execution_id="exec-456",
        remediation_status="SUCCESS",
        finding_type="S3.1",
        resource_id="bucket-name",
        resource_type="AwsS3Bucket",
        account_id="123456789012",
        severity="HIGH",
        region="us-east-1",
    )

    # ACT
    update_remediation_status_and_history(request)

    # ASSERT
    history_response = dynamodb.get_item(
        TableName="test-history-table",
        Key={
            "findingType": {"S": "S3.1"},
            "findingId#executionId": {"S": "new-finding-id#exec-456"},
        },
    )
    assert "Item" in history_response
    assert history_response["Item"]["remediationStatus"]["S"] == "SUCCESS"
    assert history_response["Item"]["accountId"]["S"] == "123456789012"

    del os.environ["FINDINGS_TABLE_NAME"]
    del os.environ["HISTORY_TABLE_NAME"]
    del os.environ["AWS_REGION"]
    del os.environ["HISTORY_TTL_DAYS"]


@mock_aws
def test_update_remediation_status_and_history_invalid_request():
    # ARRANGE
    os.environ["AWS_REGION"] = "us-east-1"

    request = RemediationUpdateRequest(
        finding_id="",
        execution_id="exec-123",
        remediation_status="SUCCESS",
        finding_type="EC2.1",
    )

    # ACT
    update_remediation_status_and_history(request)

    # ASSERT - Should return early without error
    del os.environ["AWS_REGION"]


@mock_aws
def test_update_remediation_status_and_history_with_error(mocker):
    # ARRANGE
    dynamodb = create_dynamodb_tables()

    dynamodb.put_item(
        TableName="test-findings-table",
        Item={
            "findingType": {"S": "EC2.1"},
            "findingId": {"S": "test-finding-id"},
        },
    )

    dynamodb.put_item(
        TableName="test-history-table",
        Item={
            "findingType": {"S": "EC2.1"},
            "findingId#executionId": {"S": "test-finding-id#exec-789"},
            "remediationStatus": {"S": "IN_PROGRESS"},
        },
    )

    os.environ["FINDINGS_TABLE_NAME"] = "test-findings-table"
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"
    os.environ["AWS_REGION"] = "us-east-1"

    mocker.patch(
        "layer.remediation_data_service.AWSCachedClient"
    ).return_value.get_connection.return_value = dynamodb

    request = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="exec-789",
        remediation_status="FAILED",
        finding_type="EC2.1",
        error="Lambda function timeout",
    )

    # ACT
    update_remediation_status_and_history(request)

    # ASSERT
    finding_response = dynamodb.get_item(
        TableName="test-findings-table",
        Key={"findingType": {"S": "EC2.1"}, "findingId": {"S": "test-finding-id"}},
    )
    assert finding_response["Item"]["error"]["S"] == "Lambda function timeout"

    history_response = dynamodb.get_item(
        TableName="test-history-table",
        Key={
            "findingType": {"S": "EC2.1"},
            "findingId#executionId": {"S": "test-finding-id#exec-789"},
        },
    )
    assert history_response["Item"]["error"]["S"] == "Lambda function timeout"

    del os.environ["FINDINGS_TABLE_NAME"]
    del os.environ["HISTORY_TABLE_NAME"]
    del os.environ["AWS_REGION"]
