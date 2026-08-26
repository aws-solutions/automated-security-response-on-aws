# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from datetime import datetime, timedelta

from layer.history_repository import (
    RemediationUpdateRequest,
    build_create_item,
    build_update_item,
    calculate_ttl_timestamp,
    transact_create_history_and_update_finding,
    transact_update_finding_and_history,
)
from moto import mock_aws

from .conftest import create_dynamodb_tables


def test_calculate_history_ttl_timestamp():
    # ARRANGE
    timestamp = "2024-01-01T00:00:00Z"
    os.environ["HISTORY_TTL_DAYS"] = "365"

    # ACT
    ttl = calculate_ttl_timestamp(timestamp)

    # ASSERT
    expected_ttl = int(
        (
            datetime.fromisoformat("2024-01-01T00:00:00+00:00") + timedelta(days=365)
        ).timestamp()
    )
    assert ttl == expected_ttl

    del os.environ["HISTORY_TTL_DAYS"]


def test_remediation_update_request_validation_success():
    # ARRANGE
    request = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="exec-123",
        remediation_status="SUCCESS",
        finding_type="EC2.1",
    )

    # ACT
    result = request.validate()

    # ASSERT
    assert result is True


def test_remediation_update_request_validation_failure():
    # ARRANGE
    request = RemediationUpdateRequest(
        finding_id="",
        execution_id="exec-123",
        remediation_status="SUCCESS",
        finding_type="EC2.1",
    )

    # ACT
    result = request.validate()

    # ASSERT
    assert result is False


def test_build_history_create_item_basic():
    # ARRANGE
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"
    os.environ["HISTORY_TTL_DAYS"] = "365"

    request = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="exec-123",
        remediation_status="SUCCESS",
        finding_type="EC2.1",
        resource_id="i-123",
        resource_type="AwsEc2Instance",
        account_id="123456789012",
        severity="HIGH",
        region="us-east-1",
        last_updated_by="Automated",
    )

    # ACT
    result = build_create_item(request)

    # ASSERT
    assert "Put" in result
    assert result["Put"]["TableName"] == "test-history-table"
    assert result["Put"]["Item"]["findingType"] == {"S": "EC2.1"}
    assert result["Put"]["Item"]["findingId"] == {"S": "test-finding-id"}
    assert result["Put"]["Item"]["executionId"] == {"S": "exec-123"}
    assert result["Put"]["Item"]["remediationStatus"] == {"S": "SUCCESS"}
    assert result["Put"]["Item"]["resourceId"] == {"S": "i-123"}
    assert result["Put"]["Item"]["accountId"] == {"S": "123456789012"}
    assert "findingId#executionId" in result["Put"]["Item"]
    assert "expireAt" in result["Put"]["Item"]

    del os.environ["HISTORY_TABLE_NAME"]
    del os.environ["HISTORY_TTL_DAYS"]


def test_build_history_create_item_with_error():
    # ARRANGE
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"

    request = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="exec-123",
        remediation_status="FAILED",
        finding_type="S3.1",
        resource_id="bucket-name",
        resource_type="AwsS3Bucket",
        account_id="123456789012",
        severity="MEDIUM",
        region="us-west-2",
        last_updated_by="Automated",
        error="Test error message",
    )

    # ACT
    result = build_create_item(request)

    # ASSERT
    assert result["Put"]["Item"]["error"] == {"S": "Test error message"}
    assert result["Put"]["Item"]["remediationStatus"] == {"S": "FAILED"}

    del os.environ["HISTORY_TABLE_NAME"]


def test_build_history_create_item_with_empty_optional_fields():
    # ARRANGE
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"

    request = RemediationUpdateRequest(
        finding_id="test-finding-id",
        execution_id="exec-123",
        remediation_status="SUCCESS",
        finding_type="EC2.1",
        resource_id=None,
        resource_type=None,
        account_id=None,
        severity=None,
        region=None,
    )

    # ACT
    result = build_create_item(request)

    # ASSERT
    item = result["Put"]["Item"]
    assert "accountId" not in item
    assert "resourceId" not in item
    assert "resourceType" not in item
    assert "severity" not in item
    assert "region" not in item
    assert item["findingType"] == {"S": "EC2.1"}
    assert item["remediationStatus"] == {"S": "SUCCESS"}

    del os.environ["HISTORY_TABLE_NAME"]


def test_build_history_update_item():
    # ARRANGE
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"

    # ACT
    result = build_update_item(
        "test-finding-id",
        "exec-123",
        "FAILED",
        "S3.1",
        error="Test error message",
    )

    # ASSERT
    assert "Update" in result
    assert result["Update"]["TableName"] == "test-history-table"
    assert result["Update"]["Key"]["findingType"] == {"S": "S3.1"}
    assert result["Update"]["Key"]["findingId#executionId"] == {
        "S": "test-finding-id#exec-123"
    }
    assert "remediationStatus = :rs" in result["Update"]["UpdateExpression"]
    assert "#err = :err" in result["Update"]["UpdateExpression"]
    assert result["Update"]["ExpressionAttributeValues"][":rs"] == {"S": "FAILED"}
    assert result["Update"]["ExpressionAttributeValues"][":err"] == {
        "S": "Test error message"
    }
    assert result["Update"]["ExpressionAttributeNames"]["#err"] == "error"

    del os.environ["HISTORY_TABLE_NAME"]


@mock_aws
def test_transact_update_finding_and_history():
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

    # ACT
    transact_update_finding_and_history(
        dynamodb, "EC2.1", "test-finding-id", "exec-123", "SUCCESS"
    )

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


@mock_aws
def test_transact_create_history_and_update_finding():
    # ARRANGE
    dynamodb = create_dynamodb_tables()

    dynamodb.put_item(
        TableName="test-findings-table",
        Item={
            "findingType": {"S": "S3.1"},
            "findingId": {"S": "new-finding-id"},
            "remediationStatus": {"S": "IN_PROGRESS"},
        },
    )

    os.environ["FINDINGS_TABLE_NAME"] = "test-findings-table"
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"
    os.environ["HISTORY_TTL_DAYS"] = "365"

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
        last_updated_by="Automated",
    )

    # ACT
    transact_create_history_and_update_finding(dynamodb, request)

    # ASSERT
    finding_response = dynamodb.get_item(
        TableName="test-findings-table",
        Key={"findingType": {"S": "S3.1"}, "findingId": {"S": "new-finding-id"}},
    )
    assert finding_response["Item"]["remediationStatus"]["S"] == "SUCCESS"

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
    del os.environ["HISTORY_TTL_DAYS"]
