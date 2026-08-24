# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os

import pytest
from layer.findings_repository import (
    build_update_item,
    extract_partial_finding_data,
    get,
    get_metric_attributes,
    update,
)
from moto import mock_aws

from .conftest import create_dynamodb_tables


@pytest.fixture(scope="function")
def dynamodb_table():
    with mock_aws():
        dynamodb = create_dynamodb_tables()
        yield dynamodb


def test_get_finding_success(dynamodb_table):
    # ARRANGE
    dynamodb_table.put_item(
        TableName="test-findings-table",
        Item={
            "findingType": {"S": "EC2.1"},
            "findingId": {"S": "test-finding-id"},
            "accountId": {"S": "123456789012"},
            "resourceId": {"S": "i-1234567890abcdef0"},
            "resourceType": {"S": "AwsEc2Instance"},
            "severity": {"S": "HIGH"},
        },
    )

    # ACT
    result = get(dynamodb_table, "EC2.1", "test-finding-id")

    # ASSERT
    assert result is not None
    assert result["accountId"]["S"] == "123456789012"
    assert result["resourceId"]["S"] == "i-1234567890abcdef0"
    assert result["resourceType"]["S"] == "AwsEc2Instance"
    assert result["severity"]["S"] == "HIGH"


def test_get_finding_not_found(dynamodb_table):
    # ACT
    result = get(dynamodb_table, "EC2.1", "nonexistent-finding")

    # ASSERT
    assert result is None


def test_get_metric_attributes_success(dynamodb_table):
    # ARRANGE
    dynamodb_table.put_item(
        TableName="test-findings-table",
        Item={
            "findingType": {"S": "S3.1"},
            "findingId": {"S": "test-finding-id"},
            "firstDetectedTime": {"S": "2024-01-05T00:00:00Z"},
            "hasFindingNotificationsEnabled": {"BOOL": True},
            "hasFindingRemediationDeadlineConfigured": {"BOOL": False},
        },
    )

    # ACT
    result = get_metric_attributes(dynamodb_table, "S3.1", "test-finding-id")

    # ASSERT
    assert result == {
        "first_detected_time": "2024-01-05T00:00:00Z",
        "finding_notifications_enabled": True,
        "finding_remediation_deadline_configured": False,
    }


def test_get_metric_attributes_not_found(dynamodb_table):
    # ACT
    result = get_metric_attributes(dynamodb_table, "S3.1", "nonexistent-finding")

    # ASSERT
    assert result == {}


def test_get_metric_attributes_omits_absent_attributes(dynamodb_table):
    # ARRANGE: a finding written before the metric attributes existed carries none of them
    dynamodb_table.put_item(
        TableName="test-findings-table",
        Item={
            "findingType": {"S": "S3.1"},
            "findingId": {"S": "legacy-finding-id"},
            "firstDetectedTime": {"S": "2024-01-05T00:00:00Z"},
        },
    )

    # ACT
    result = get_metric_attributes(dynamodb_table, "S3.1", "legacy-finding-id")

    # ASSERT: only the present attribute is returned
    assert result == {"first_detected_time": "2024-01-05T00:00:00Z"}


@mock_aws
def test_update_finding():
    # ARRANGE
    dynamodb = create_dynamodb_tables()
    table_name = "test-findings-table"

    dynamodb.put_item(
        TableName=table_name,
        Item={
            "findingType": {"S": "EC2.1"},
            "findingId": {"S": "test-finding-id"},
            "remediationStatus": {"S": "IN_PROGRESS"},
        },
    )

    os.environ["FINDINGS_TABLE_NAME"] = table_name

    # ACT
    update(dynamodb, "EC2.1", "test-finding-id", "SUCCESS", "exec-123")

    # ASSERT
    response = dynamodb.get_item(
        TableName=table_name,
        Key={"findingType": {"S": "EC2.1"}, "findingId": {"S": "test-finding-id"}},
    )
    assert response["Item"]["remediationStatus"]["S"] == "SUCCESS"
    assert response["Item"]["executionId"]["S"] == "exec-123"

    del os.environ["FINDINGS_TABLE_NAME"]


def test_build_finding_update_item_basic():
    # ACT
    result = build_update_item("EC2.1", "test-finding-id", "SUCCESS", "exec-123")

    # ASSERT
    assert "Update" in result
    assert result["Update"]["TableName"] == os.getenv("FINDINGS_TABLE_NAME", "")
    assert result["Update"]["Key"] == {
        "findingType": {"S": "EC2.1"},
        "findingId": {"S": "test-finding-id"},
    }
    assert "remediationStatus = :rs" in result["Update"]["UpdateExpression"]
    assert result["Update"]["ExpressionAttributeValues"][":rs"] == {"S": "SUCCESS"}
    assert result["Update"]["ExpressionAttributeValues"][":eid"] == {"S": "exec-123"}


def test_build_finding_update_item_with_error():
    # ACT
    result = build_update_item(
        "EC2.1", "test-finding-id", "FAILED", "exec-123", "Test error message"
    )

    # ASSERT
    assert "#err = :err" in result["Update"]["UpdateExpression"]
    assert result["Update"]["ExpressionAttributeValues"][":err"] == {
        "S": "Test error message"
    }
    assert result["Update"]["ExpressionAttributeNames"]["#err"] == "error"


def test_build_finding_update_item_without_error():
    # ACT
    result = build_update_item("S3.1", "test-finding-id", "IN_PROGRESS", "exec-456")

    # ASSERT
    assert "ExpressionAttributeNames" not in result["Update"]
    assert ":err" not in result["Update"]["ExpressionAttributeValues"]


@mock_aws
def test_update_finding_with_error():
    # ARRANGE
    dynamodb = create_dynamodb_tables()
    table_name = "test-findings-table"

    dynamodb.put_item(
        TableName=table_name,
        Item={
            "findingType": {"S": "EC2.1"},
            "findingId": {"S": "test-finding-id"},
            "remediationStatus": {"S": "IN_PROGRESS"},
        },
    )

    os.environ["FINDINGS_TABLE_NAME"] = table_name

    # ACT
    update(dynamodb, "EC2.1", "test-finding-id", "FAILED", "exec-123", "Test error")

    # ASSERT
    response = dynamodb.get_item(
        TableName=table_name,
        Key={"findingType": {"S": "EC2.1"}, "findingId": {"S": "test-finding-id"}},
    )
    assert response["Item"]["remediationStatus"]["S"] == "FAILED"
    assert response["Item"]["error"]["S"] == "Test error"

    del os.environ["FINDINGS_TABLE_NAME"]


def test_extract_partial_finding_data():
    # ARRANGE
    item = {
        "accountId": {"S": "123456789012"},
        "resourceId": {"S": "i-1234567890abcdef0"},
        "resourceType": {"S": "AwsEc2Instance"},
        "resourceTypeNormalized": {"S": "EC2Instance"},
        "severity": {"S": "HIGH"},
        "region": {"S": "us-east-1"},
        "lastUpdatedBy": {"S": "Automated"},
    }

    # ACT
    result = extract_partial_finding_data(item)

    # ASSERT
    assert result["accountId"] == "123456789012"
    assert result["resourceId"] == "i-1234567890abcdef0"
    assert result["resourceType"] == "AwsEc2Instance"
    assert result["resourceTypeNormalized"] == "EC2Instance"
    assert result["severity"] == "HIGH"
    assert result["region"] == "us-east-1"
    assert result["lastUpdatedBy"] == "Automated"


def test_extract_partial_finding_data_missing_fields():
    # ARRANGE
    item = {
        "accountId": {"S": "123456789012"},
        "resourceId": {"S": "i-1234567890abcdef0"},
    }

    # ACT
    result = extract_partial_finding_data(item)

    # ASSERT
    assert result["accountId"] == "123456789012"
    assert result["resourceId"] == "i-1234567890abcdef0"
    assert "resourceType" not in result
    assert "severity" not in result
