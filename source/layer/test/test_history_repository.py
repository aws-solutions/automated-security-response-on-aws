# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from datetime import datetime, timedelta
from typing import Any

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


# ═══════════════════════════════════════════════════════════════
# Rollback field tests
# ═══════════════════════════════════════════════════════════════


def test_add_optional_string_fields():
    from layer.history_repository import _add_optional_string_fields

    item: dict[str, Any] = {}
    _add_optional_string_fields(
        item,
        {
            "ssmExecutionId": "exec-123",
            "rollbackDescription": "Disable key rotation",
            "snapshotVersionId": None,
            "emptyField": "",
        },
    )
    assert item["ssmExecutionId"] == {"S": "exec-123"}
    assert item["rollbackDescription"] == {"S": "Disable key rotation"}
    assert "snapshotVersionId" not in item
    assert "emptyField" not in item


def test_build_create_item_with_rollback_fields():
    request = RemediationUpdateRequest(
        finding_id="finding-1",
        execution_id="exec-1",
        remediation_status="SUCCESS",
        finding_type="KMS.4",
        resource_id="key-123",
        resource_type="AwsKmsKey",
        account_id="111111111111",
        severity="50",
        region="us-east-1",
        last_updated_by="Automated",
        ssm_execution_id="ssm-exec-abc",
        rollback_available=True,
        rollback_description="Disable key rotation for key-123",
        snapshot_version_id="ver-xyz",
    )
    result = build_create_item(request)
    item = result["Put"]["Item"]
    assert item["ssmExecutionId"] == {"S": "ssm-exec-abc"}
    assert item["rollbackAvailable"] == {"BOOL": True}
    assert item["rollbackDescription"] == {"S": "Disable key rotation for key-123"}
    assert item["snapshotVersionId"] == {"S": "ver-xyz"}


def test_build_create_item_without_rollback_fields():
    request = RemediationUpdateRequest(
        finding_id="finding-1",
        execution_id="exec-1",
        remediation_status="SUCCESS",
        finding_type="KMS.4",
        resource_id="key-123",
        resource_type="AwsKmsKey",
        account_id="111111111111",
        severity="50",
        region="us-east-1",
        last_updated_by="Automated",
    )
    result = build_create_item(request)
    item = result["Put"]["Item"]
    assert "ssmExecutionId" not in item
    assert "rollbackAvailable" not in item
    assert "rollbackDescription" not in item
    assert "snapshotVersionId" not in item


def test_build_update_item_with_rollback_fields():
    result = build_update_item(
        finding_id="finding-1",
        execution_id="exec-1",
        remediation_status="SUCCESS",
        finding_type="KMS.4",
        ssm_execution_id="ssm-exec-abc",
        rollback_available=True,
        rollback_description="Disable key rotation",
        snapshot_version_id="ver-xyz",
    )
    update = result["Update"]
    assert ":sei" in update["ExpressionAttributeValues"]
    assert update["ExpressionAttributeValues"][":sei"] == {"S": "ssm-exec-abc"}
    assert ":ra" in update["ExpressionAttributeValues"]
    assert update["ExpressionAttributeValues"][":ra"] == {"BOOL": True}
    assert ":rdes" in update["ExpressionAttributeValues"]
    assert ":svid" in update["ExpressionAttributeValues"]
    assert "ssmExecutionId" in update["UpdateExpression"]
    assert "rollbackAvailable" in update["UpdateExpression"]


def test_build_update_item_rollback_available_false():
    result = build_update_item(
        finding_id="finding-1",
        execution_id="exec-1",
        remediation_status="ROLLBACK_SUCCESS",
        finding_type="KMS.4",
        rollback_available=False,
    )
    update = result["Update"]
    assert update["ExpressionAttributeValues"][":ra"] == {"BOOL": False}


def test_success_update_clears_a_previous_attempts_error() -> None:
    """A retry that succeeds must REMOVE the error, not leave it beside SUCCESS.

    `SET` alone never removes an attribute, so before this the failed attempt's
    message survived into the successful row and `get_execution_status` reported a
    SUCCESS execution carrying a stale AccessDenied. Observed live on 2026-09-17:
    the S3.17 finding's second execution came back SUCCESS with the first
    execution's "Missing required parameter: BucketName" still attached.
    """
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"

    result = build_update_item(
        "test-finding-id",
        "exec-123",
        "SUCCESS",
        "security-control/S3.17",
    )

    expression = result["Update"]["UpdateExpression"]
    assert "REMOVE #err" in expression
    # The REMOVE clause has to come after every SET assignment, or DynamoDB
    # rejects the expression outright.
    assert expression.index("SET") < expression.index("REMOVE")
    assert result["Update"]["ExpressionAttributeNames"]["#err"] == "error"
    # Nothing is assigned to the attribute being removed.
    assert ":err" not in result["Update"]["ExpressionAttributeValues"]


def test_rollback_success_also_clears_the_error() -> None:
    """The rollback path writes its own success status and can also follow a failure."""
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"

    result = build_update_item(
        "test-finding-id",
        "exec-123",
        "ROLLBACK_SUCCESS",
        "security-control/S3.17",
    )

    assert "REMOVE #err" in result["Update"]["UpdateExpression"]


def test_a_failed_status_without_a_message_keeps_the_stored_error() -> None:
    """A partial update re-asserting FAILED must not discard the real reason.

    `build_update_item` is also used to set fields like rollbackAvailable on an
    already-failed row without resupplying the message. Clearing on "no error was
    passed" rather than on success would silently drop why it failed, which is why
    the rule is scoped to the success statuses.
    """
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"

    result = build_update_item(
        "test-finding-id",
        "exec-123",
        "FAILED",
        "security-control/S3.17",
        rollback_available=False,
    )

    assert "REMOVE" not in result["Update"]["UpdateExpression"]


def test_success_with_an_explicit_error_still_records_it() -> None:
    """An explicitly supplied message wins over the clear, so callers keep control."""
    os.environ["HISTORY_TABLE_NAME"] = "test-history-table"

    result = build_update_item(
        "test-finding-id",
        "exec-123",
        "SUCCESS",
        "security-control/S3.17",
        error="partial success detail",
    )

    expression = result["Update"]["UpdateExpression"]
    assert "#err = :err" in expression
    assert "REMOVE" not in expression
    assert result["Update"]["ExpressionAttributeValues"][":err"] == {
        "S": "partial success detail"
    }
