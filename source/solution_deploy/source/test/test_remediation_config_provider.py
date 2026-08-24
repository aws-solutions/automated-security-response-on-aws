# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test remediation config provider"""

import json
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import boto3
from aws_lambda_powertools.utilities.data_classes import (
    CloudFormationCustomResourceEvent,
)
from aws_lambda_powertools.utilities.typing import LambdaContext
from cfnresponse import SUCCESS
from moto import mock_aws
from remediation_config_provider import (
    build_default_control_item,
    get_control_descriptions,
    lambda_handler,
)

os.environ["AWS_REGION"] = "us-east-1"
os.environ["REFERENCE_BUCKET_NAME"] = "test-solutions-bucket"
os.environ["REFERENCE_BUCKET_PARTITION"] = "aws"
os.environ["SOLUTION_ID"] = "SO0000"
os.environ["SOLUTION_TMN"] = "automated-security-response-on-aws"
os.environ["SOLUTION_VERSION"] = "v3.0.0"

TEST_CONTROLS = {
    "solutionVersion": "v3.0.0",
    "supportedControls": ["S3.1", "S3.2", "EC2.1", "IAM.1"],
}

FIXED_TIMESTAMP = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
FIXED_TIMESTAMP_ISO = "2024-01-15T10:30:00Z"

# Moto does not implement securityhub.batch_get_security_controls, so we stub
# get_control_descriptions instead of relying on @mock_aws for Security Hub calls.
MOCK_DESCRIPTIONS = {
    "S3.1": "S3 general purpose buckets should have block public access settings enabled",
    "S3.2": "S3 general purpose buckets should block public read access",
    "EC2.1": "Amazon EBS snapshots should not be publicly restorable",
    "IAM.1": "IAM policies should not allow full '*' administrative privileges",
}


def get_mock_context() -> LambdaContext:
    """Create a mock LambdaContext object"""
    context = MagicMock(spec=LambdaContext)
    context.function_name = "test-function"
    context.function_version = "$LATEST"
    context.invoked_function_arn = (
        "arn:aws:lambda:us-east-1:123456789012:function:test-function"
    )
    context.memory_limit_in_mb = 128
    context.remaining_time_in_millis = lambda: 30000
    context.aws_request_id = "test-request-id"
    context.log_group_name = "/aws/lambda/test-function"
    context.log_stream_name = "2023/01/01/[$LATEST]test-stream"
    return context


def get_event(request_type, table_name="test-table"):
    event_dict = {
        "RequestType": request_type,
        "ResourceProperties": {
            "TableName": table_name,
        },
        "ResponseURL": "https://test-url",
        "StackId": "test-stack",
        "RequestId": "test-request",
        "LogicalResourceId": "test-resource",
        "PhysicalResourceId": "test-physical-id",
    }
    return CloudFormationCustomResourceEvent(event_dict)


@mock_aws
@patch("cfnresponse.send")
@patch(
    "remediation_config_provider.get_control_descriptions",
    return_value=MOCK_DESCRIPTIONS,
)
@patch("remediation_config_provider.datetime")
def test_create_populates_table(mock_datetime, mock_get_descriptions, mock_cfnresponse):
    """Test Create request populates table with supported controls and descriptions"""
    # ARRANGE
    mock_datetime.now.return_value = FIXED_TIMESTAMP

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-solutions-bucket")
    s3.put_object(
        Bucket="test-solutions-bucket",
        Key="automated-security-response-on-aws/v3.0.0/supported-controls.json",
        Body=json.dumps(TEST_CONTROLS),
    )

    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="test-table",
        KeySchema=[{"AttributeName": "controlId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "controlId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    # ACT
    event = get_event("Create")
    context = get_mock_context()
    lambda_handler(event, context)

    # ASSERT
    response = table.scan()
    items = response["Items"]

    assert len(items) == 4
    control_ids = {item["controlId"] for item in items}
    assert control_ids == {"S3.1", "S3.2", "EC2.1", "IAM.1"}

    for item in items:
        assert item["automatedRemediationEnabled"] is False
        assert item.get("filters", set()) == set()
        assert item["filterMode"] == "include"
        assert item["version"] == 1
        assert item["lastModified"] == FIXED_TIMESTAMP_ISO
        assert item["modifiedBy"] == "system"
        assert item["description"] == MOCK_DESCRIPTIONS[item["controlId"]]

    # Verify the timestamp was generated as timezone-aware UTC, not a naive
    # datetime.now() — a regression to datetime.now() without timezone.utc
    # would otherwise pass because the mock ignores call arguments.
    mock_datetime.now.assert_called_with(timezone.utc)

    mock_get_descriptions.assert_called_once_with(TEST_CONTROLS["supportedControls"])
    mock_cfnresponse.assert_called_once()
    args = mock_cfnresponse.call_args[0]
    assert args[2] == SUCCESS


@mock_aws
@patch("cfnresponse.send")
@patch("remediation_config_provider.get_control_descriptions")
def test_update_adds_new_controls_and_preserves_custom_controls(
    mock_get_descriptions, mock_cfnresponse
):
    """Test Update request adds new controls and preserves custom user-added controls"""
    # ARRANGE
    mock_get_descriptions.return_value = {
        "S3.3": "S3.3 description",
        "RDS.1": "RDS.1 description",
        "S3.1": "S3.1 description",
        "S3.2": "S3.2 description",
        "EC2.1": "EC2.1 description",
        "IAM.1": "IAM.1 description",
        "CUSTOM.1": "CUSTOM.1 description",
    }

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-solutions-bucket")
    updated_controls = {
        "solutionVersion": "v3.1.0",
        "supportedControls": [
            "S3.1",
            "S3.3",
            "RDS.1",
        ],
    }
    s3.put_object(
        Bucket="test-solutions-bucket",
        Key="automated-security-response-on-aws/v3.0.0/supported-controls.json",
        Body=json.dumps(updated_controls),
    )

    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="test-table",
        KeySchema=[{"AttributeName": "controlId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "controlId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    table.put_item(Item={"controlId": "S3.1", "automatedRemediationEnabled": True})
    table.put_item(Item={"controlId": "S3.2", "automatedRemediationEnabled": False})
    table.put_item(Item={"controlId": "EC2.1", "automatedRemediationEnabled": False})
    table.put_item(Item={"controlId": "IAM.1", "automatedRemediationEnabled": False})
    table.put_item(Item={"controlId": "CUSTOM.1", "automatedRemediationEnabled": True})

    # ACT
    event = get_event("Update")
    context = get_mock_context()
    lambda_handler(event, context)

    # ASSERT
    response = table.scan()
    items = {item["controlId"]: item for item in response["Items"]}

    assert len(items) == 7
    assert set(items.keys()) == {
        "S3.1",
        "S3.2",
        "EC2.1",
        "IAM.1",
        "CUSTOM.1",
        "S3.3",
        "RDS.1",
    }

    assert items["S3.1"]["automatedRemediationEnabled"] is True
    assert items["S3.2"]["automatedRemediationEnabled"] is False
    assert items["EC2.1"]["automatedRemediationEnabled"] is False
    assert items["IAM.1"]["automatedRemediationEnabled"] is False
    assert items["CUSTOM.1"]["automatedRemediationEnabled"] is True

    assert items["S3.3"]["automatedRemediationEnabled"] is False
    assert items["RDS.1"]["automatedRemediationEnabled"] is False

    assert items["S3.3"]["description"] == "S3.3 description"
    assert items["RDS.1"]["description"] == "RDS.1 description"

    for control_id, item in items.items():
        assert (
            item.get("filters", set()) == set()
        ), f"{control_id} should have empty filters"
        assert (
            item["filterMode"] == "include"
        ), f"{control_id} should have include filterMode"
        assert item["version"] == 1, f"{control_id} should have version 1"

    mock_cfnresponse.assert_called_once()
    args = mock_cfnresponse.call_args[0]
    assert args[2] == SUCCESS


@mock_aws
@patch("cfnresponse.send")
def test_delete_no_op(mock_cfnresponse):
    """Test Delete request does nothing"""
    # Setup minimal resources
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-solutions-bucket")

    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    dynamodb.create_table(
        TableName="test-table",
        KeySchema=[{"AttributeName": "controlId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "controlId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    # Execute lambda
    event = get_event("Delete")
    context = get_mock_context()
    lambda_handler(event, context)

    mock_cfnresponse.assert_called_once()
    args = mock_cfnresponse.call_args[0]
    assert args[2] == SUCCESS


@mock_aws
@patch("cfnresponse.send")
@patch(
    "remediation_config_provider.get_control_descriptions",
    return_value=MOCK_DESCRIPTIONS,
)
def test_bucket_suffix_aws_cn(mock_get_descriptions, mock_cfnresponse):
    """Test bucket suffix for aws-cn partition"""
    original_region = os.environ["AWS_REGION"]
    original_partition = os.environ["REFERENCE_BUCKET_PARTITION"]

    os.environ["AWS_REGION"] = "cn-north-1"
    os.environ["REFERENCE_BUCKET_PARTITION"] = "aws-cn"

    s3_cn = boto3.client("s3", region_name="cn-north-1")
    s3_cn.create_bucket(
        Bucket="test-solutions-bucket-cn",
        CreateBucketConfiguration={"LocationConstraint": "cn-north-1"},
    )
    s3_cn.put_object(
        Bucket="test-solutions-bucket-cn",
        Key="automated-security-response-on-aws/v3.0.0/supported-controls.json",
        Body=json.dumps(TEST_CONTROLS),
    )

    dynamodb_cn = boto3.client("dynamodb", region_name="cn-north-1")
    dynamodb_cn.create_table(
        TableName="test-table",
        KeySchema=[{"AttributeName": "controlId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "controlId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    event = get_event("Create")
    context = get_mock_context()
    lambda_handler(event, context)

    response = dynamodb_cn.scan(TableName="test-table")
    assert len(response["Items"]) == 4

    mock_cfnresponse.assert_called_once()
    args = mock_cfnresponse.call_args[0]
    assert args[2] == SUCCESS

    os.environ["AWS_REGION"] = original_region
    os.environ["REFERENCE_BUCKET_PARTITION"] = original_partition


@mock_aws
@patch("cfnresponse.send")
@patch(
    "remediation_config_provider.get_control_descriptions",
    return_value=MOCK_DESCRIPTIONS,
)
def test_custom_reference_bucket_region(mock_get_descriptions, mock_cfnresponse):
    """Test custom reference bucket region override"""
    original_region = os.environ["AWS_REGION"]

    os.environ["AWS_REGION"] = "us-west-2"
    os.environ["CUSTOM_REFERENCE_BUCKET_REGION"] = "us-west-2"

    s3_west = boto3.client("s3", region_name="us-west-2")
    s3_west.create_bucket(
        Bucket="test-solutions-bucket",
        CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
    )
    s3_west.put_object(
        Bucket="test-solutions-bucket",
        Key="automated-security-response-on-aws/v3.0.0/supported-controls.json",
        Body=json.dumps(TEST_CONTROLS),
    )

    dynamodb_west = boto3.client("dynamodb", region_name="us-west-2")
    dynamodb_west.create_table(
        TableName="test-table",
        KeySchema=[{"AttributeName": "controlId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "controlId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    event = get_event("Create")
    context = get_mock_context()
    lambda_handler(event, context)

    response = dynamodb_west.scan(TableName="test-table")
    assert len(response["Items"]) == 4

    mock_cfnresponse.assert_called_once()
    args = mock_cfnresponse.call_args[0]
    assert args[2] == SUCCESS

    os.environ["AWS_REGION"] = original_region
    del os.environ["CUSTOM_REFERENCE_BUCKET_REGION"]


@patch("cfnresponse.send")
def test_missing_table_name_fails(mock_cfnresponse):
    """Test missing TableName property fails"""
    event_dict = {
        "RequestType": "Create",
        "ResourceProperties": {},
        "ResponseURL": "https://test-url",
        "StackId": "test-stack",
        "RequestId": "test-request",
        "LogicalResourceId": "test-resource",
        "PhysicalResourceId": "test-physical-id",
    }
    event = CloudFormationCustomResourceEvent(event_dict)

    context = get_mock_context()
    lambda_handler(event, context)

    args = mock_cfnresponse.call_args[0]
    assert args[2] == "FAILED"


@mock_aws
@patch("cfnresponse.send")
@patch("remediation_config_provider.get_control_descriptions", return_value={})
def test_update_is_idempotent_preserves_existing_schema_values(
    mock_get_descriptions, mock_cfnresponse
):
    """Test Update request is idempotent and preserves existing schema values"""
    # ARRANGE
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-solutions-bucket")
    s3.put_object(
        Bucket="test-solutions-bucket",
        Key="automated-security-response-on-aws/v3.0.0/supported-controls.json",
        Body=json.dumps(TEST_CONTROLS),
    )

    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="test-table",
        KeySchema=[{"AttributeName": "controlId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "controlId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    table.put_item(
        Item={
            "controlId": "S3.1",
            "description": "Existing S3.1 description",
            "automatedRemediationEnabled": True,
            "filters": {"filter-1", "filter-2"},
            "filterMode": "exclude",
            "version": 5,
            "lastModified": "2024-01-15T10:30:00Z",
            "modifiedBy": "admin-user",
        }
    )
    table.put_item(
        Item={
            "controlId": "S3.2",
            "description": "Existing S3.2 description",
            "automatedRemediationEnabled": False,
            "filterMode": "include",
            "version": 1,
            "lastModified": "",
            "modifiedBy": "",
        }
    )

    # ACT
    event = get_event("Update")
    context = get_mock_context()
    lambda_handler(event, context)

    # ASSERT
    response = table.scan()
    items = {item["controlId"]: item for item in response["Items"]}

    assert len(items) == 4
    assert set(items.keys()) == {"S3.1", "S3.2", "EC2.1", "IAM.1"}

    assert items["S3.1"]["automatedRemediationEnabled"] is True
    assert items["S3.1"]["filters"] == {"filter-1", "filter-2"}
    assert items["S3.1"]["filterMode"] == "exclude"
    assert items["S3.1"]["version"] == 5
    assert items["S3.1"]["lastModified"] == "2024-01-15T10:30:00Z"
    assert items["S3.1"]["modifiedBy"] == "admin-user"
    assert items["S3.1"]["description"] == "Existing S3.1 description"

    assert items["S3.2"]["automatedRemediationEnabled"] is False
    assert items["S3.2"].get("filters", set()) == set()
    assert items["S3.2"]["filterMode"] == "include"
    assert items["S3.2"]["version"] == 1
    assert items["S3.2"]["description"] == "Existing S3.2 description"

    assert items["EC2.1"]["automatedRemediationEnabled"] is False
    assert items["EC2.1"].get("filters", set()) == set()
    assert items["EC2.1"]["filterMode"] == "include"
    assert items["EC2.1"]["version"] == 1

    assert items["IAM.1"]["automatedRemediationEnabled"] is False
    assert items["IAM.1"].get("filters", set()) == set()
    assert items["IAM.1"]["filterMode"] == "include"
    assert items["IAM.1"]["version"] == 1

    mock_cfnresponse.assert_called_once()
    args = mock_cfnresponse.call_args[0]
    assert args[2] == SUCCESS


@patch("remediation_config_provider.datetime")
def test_build_default_control_item_omits_empty_filters(mock_datetime):
    """Test build_default_control_item does not include filters key to avoid DynamoDB empty set error.

    DynamoDB does not allow empty sets (ValidationException: An number set may not be empty).
    The application treats a missing 'filters' attribute as an empty set.
    """
    # ARRANGE
    mock_datetime.now.return_value = FIXED_TIMESTAMP
    control_id = "TEST.1"
    description = "Test control description"

    # ACT
    item = build_default_control_item(control_id, description)

    # ASSERT
    assert (
        "filters" not in item
    ), "filters key should be omitted to avoid DynamoDB empty set error"
    assert item["controlId"] == control_id
    assert item["description"] == description
    assert item["automatedRemediationEnabled"] is False
    assert item["filterMode"] == "include"
    assert item["version"] == 1
    assert item["lastModified"] == FIXED_TIMESTAMP_ISO
    assert item["modifiedBy"] == "system"
    mock_datetime.now.assert_called_with(timezone.utc)


@patch("remediation_config_provider.datetime")
def test_build_default_control_item_defaults_description_to_empty(mock_datetime):
    """Test build_default_control_item defaults description to empty string when not provided."""
    # ARRANGE
    mock_datetime.now.return_value = FIXED_TIMESTAMP

    # ACT
    item = build_default_control_item("TEST.1")

    # ASSERT
    assert item["description"] == ""


@patch("remediation_config_provider.boto3")
def test_get_control_descriptions_returns_mapping(mock_boto3):
    """Test get_control_descriptions returns a controlId -> description mapping."""
    # ARRANGE
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client
    mock_client.batch_get_security_controls.return_value = {
        "SecurityControls": [
            {"SecurityControlId": "S3.1", "Description": "S3.1 desc"},
            {"SecurityControlId": "EC2.1", "Description": "EC2.1 desc"},
        ],
        "UnprocessedIds": [],
    }

    # ACT
    result = get_control_descriptions(["S3.1", "EC2.1"])

    # ASSERT
    assert result == {"S3.1": "S3.1 desc", "EC2.1": "EC2.1 desc"}
    mock_client.batch_get_security_controls.assert_called_once_with(
        SecurityControlIds=["S3.1", "EC2.1"]
    )


@patch("remediation_config_provider.boto3")
def test_get_control_descriptions_handles_unprocessed_ids(mock_boto3):
    """Test get_control_descriptions logs warnings for unprocessed controls."""
    # ARRANGE
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client
    mock_client.batch_get_security_controls.return_value = {
        "SecurityControls": [
            {"SecurityControlId": "S3.1", "Description": "S3.1 desc"},
        ],
        "UnprocessedIds": [
            {
                "SecurityControlId": "INVALID.1",
                "ErrorCode": "INVALID_INPUT",
                "ErrorReason": "Control not found",
            }
        ],
    }

    # ACT
    result = get_control_descriptions(["S3.1", "INVALID.1"])

    # ASSERT
    assert result == {"S3.1": "S3.1 desc"}
    assert "INVALID.1" not in result


@patch("remediation_config_provider.boto3")
def test_get_control_descriptions_handles_api_failure(mock_boto3):
    """Test get_control_descriptions returns empty dict on API failure."""
    # ARRANGE
    mock_client = MagicMock()
    mock_boto3.client.return_value = mock_client
    mock_client.batch_get_security_controls.side_effect = Exception("API error")

    # ACT
    result = get_control_descriptions(["S3.1"])

    # ASSERT
    assert result == {}


def test_get_control_descriptions_empty_list():
    """Test get_control_descriptions returns empty dict for empty input."""
    # ACT
    result = get_control_descriptions([])

    # ASSERT
    assert result == {}
