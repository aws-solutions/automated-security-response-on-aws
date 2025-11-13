# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test remediation config provider"""

import json
import os
from unittest.mock import MagicMock, patch

import boto3
from aws_lambda_powertools.utilities.data_classes import (
    CloudFormationCustomResourceEvent,
)
from aws_lambda_powertools.utilities.typing import LambdaContext
from cfnresponse import SUCCESS
from moto import mock_aws
from remediation_config_provider import lambda_handler

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
def test_create_populates_table(mock_cfnresponse):
    """Test Create request populates table with supported controls"""
    # Setup S3 bucket and file
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-solutions-bucket")
    s3.put_object(
        Bucket="test-solutions-bucket",
        Key="automated-security-response-on-aws/v3.0.0/supported-controls.json",
        Body=json.dumps(TEST_CONTROLS),
    )

    # Setup DynamoDB table
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="test-table",
        KeySchema=[{"AttributeName": "controlId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "controlId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    # Execute lambda
    event = get_event("Create")
    context = get_mock_context()
    lambda_handler(event, context)

    # Verify table contents
    response = table.scan()
    items = response["Items"]

    assert len(items) == 4
    control_ids = {item["controlId"] for item in items}
    assert control_ids == {"S3.1", "S3.2", "EC2.1", "IAM.1"}

    # Verify all controls are disabled by default
    for item in items:
        assert item["automatedRemediationEnabled"] is False

    mock_cfnresponse.assert_called_once()
    args = mock_cfnresponse.call_args[0]
    assert args[2] == SUCCESS


@mock_aws
@patch("cfnresponse.send")
def test_update_adds_removes_controls(mock_cfnresponse):
    """Test Update request adds new controls and removes obsolete ones"""
    # Setup S3 with updated controls
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-solutions-bucket")
    updated_controls = {
        "solutionVersion": "v3.1.0",
        "supportedControls": [
            "S3.1",
            "S3.3",
            "RDS.1",
        ],  # S3.2, EC2.1, IAM.1 removed; S3.3, RDS.1 added
    }
    s3.put_object(
        Bucket="test-solutions-bucket",
        Key="automated-security-response-on-aws/v3.0.0/supported-controls.json",
        Body=json.dumps(updated_controls),
    )

    # Setup DynamoDB table with existing data
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="test-table",
        KeySchema=[{"AttributeName": "controlId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "controlId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    # Pre-populate with existing controls (S3.1 enabled, others disabled)
    table.put_item(Item={"controlId": "S3.1", "automatedRemediationEnabled": True})
    table.put_item(Item={"controlId": "S3.2", "automatedRemediationEnabled": False})
    table.put_item(Item={"controlId": "EC2.1", "automatedRemediationEnabled": False})
    table.put_item(Item={"controlId": "IAM.1", "automatedRemediationEnabled": False})

    # Execute lambda
    event = get_event("Update")
    context = get_mock_context()
    lambda_handler(event, context)

    # Verify table contents
    response = table.scan()
    items = {item["controlId"]: item for item in response["Items"]}

    assert len(items) == 3
    assert set(items.keys()) == {"S3.1", "S3.3", "RDS.1"}

    # Verify S3.1 setting preserved, new controls disabled
    assert items["S3.1"]["automatedRemediationEnabled"] is True
    assert items["S3.3"]["automatedRemediationEnabled"] is False
    assert items["RDS.1"]["automatedRemediationEnabled"] is False

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
def test_bucket_suffix_aws_cn(mock_cfnresponse):
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
def test_custom_reference_bucket_region(mock_cfnresponse):
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
