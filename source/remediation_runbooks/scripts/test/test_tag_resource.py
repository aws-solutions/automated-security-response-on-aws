#!/usr/bin/env python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for tag_resource.py

These tests verify the tagging script functionality using moto for AWS service mocking.
Tests focus on services with good moto support for the Resource Groups Tagging API.
"""

import os
import sys

# Add parent directory to path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../common"))

import boto3
from botocore.config import Config
from moto import mock_aws
from tag_resource import SOLUTION_TAG_KEY, SOLUTION_TAG_VALUE, tag_resource

BOTO_CONFIG = Config(
    retries={"mode": "standard", "max_attempts": 10}, region_name="us-east-1"
)


@mock_aws
def test_tag_cloudwatch_log_group():
    """Verify tagging script successfully tags a CloudWatch log group"""
    # Arrange
    logs = boto3.client("logs", config=BOTO_CONFIG)
    log_group_name = "/aws/lambda/test-function"
    logs.create_log_group(logGroupName=log_group_name)
    resource_arn = f"arn:aws:logs:us-east-1:123456789012:log-group:{log_group_name}"

    # Act
    result = tag_resource({"ResourceArn": resource_arn}, {})

    # Assert
    assert result["success"] is True
    assert result["resourceArn"] == resource_arn
    assert result["failedResources"] == {}

    # Verify tags were applied
    tagging_client = boto3.client("resourcegroupstaggingapi", config=BOTO_CONFIG)
    resources = tagging_client.get_resources(ResourceARNList=[resource_arn])
    tags = resources["ResourceTagMappingList"][0]["Tags"]
    assert any(
        tag["Key"] == SOLUTION_TAG_KEY and tag["Value"] == SOLUTION_TAG_VALUE
        for tag in tags
    )


@mock_aws
def test_tag_dynamodb_table():
    """Verify tagging script successfully tags a DynamoDB table"""
    # Arrange
    dynamodb = boto3.client("dynamodb", config=BOTO_CONFIG)
    table_name = "test-table"
    table_response = dynamodb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    resource_arn = table_response["TableDescription"]["TableArn"]

    # Act
    result = tag_resource({"ResourceArn": resource_arn}, {})

    # Assert
    assert result["success"] is True
    assert result["resourceArn"] == resource_arn
    assert result["failedResources"] == {}

    # Verify tags were applied
    tagging_client = boto3.client("resourcegroupstaggingapi", config=BOTO_CONFIG)
    resources = tagging_client.get_resources(ResourceARNList=[resource_arn])
    tags = resources["ResourceTagMappingList"][0]["Tags"]
    assert any(
        tag["Key"] == SOLUTION_TAG_KEY and tag["Value"] == SOLUTION_TAG_VALUE
        for tag in tags
    )


def test_missing_resource_arn():
    """Verify tagging script returns error response when ResourceArn is missing"""
    # Arrange
    events = {}  # No ResourceArn provided

    # Act
    result = tag_resource(events, {})

    # Assert
    assert result["success"] is False
    assert result["resourceArn"] is None
    assert "error" in result
    assert "ResourceArn is required" in result["error"]


@mock_aws
def test_invalid_arn_format():
    """Verify tagging script handles invalid ARN format gracefully"""
    # Arrange
    invalid_arn = "not-a-valid-arn"

    # Act
    result = tag_resource({"ResourceArn": invalid_arn}, {})

    # Assert
    assert result["success"] is False
    assert result["resourceArn"] == invalid_arn
    # Either failedResources or error should be present
    assert "failedResources" in result or "error" in result


@mock_aws
def test_additional_tags_merged():
    """Verify tagging script merges additional tags with solution tag"""
    # Arrange
    logs = boto3.client("logs", config=BOTO_CONFIG)
    log_group_name = "/aws/test/additional-tags"
    logs.create_log_group(logGroupName=log_group_name)
    resource_arn = f"arn:aws:logs:us-east-1:123456789012:log-group:{log_group_name}"

    additional_tags = {"Environment": "Test", "Owner": "SecurityTeam"}

    # Act
    result = tag_resource(
        {"ResourceArn": resource_arn, "AdditionalTags": additional_tags}, {}
    )

    # Assert
    assert result["success"] is True

    # Verify all tags were applied
    tagging_client = boto3.client("resourcegroupstaggingapi", config=BOTO_CONFIG)
    resources = tagging_client.get_resources(ResourceARNList=[resource_arn])
    tags = resources["ResourceTagMappingList"][0]["Tags"]

    # Check solution tag
    assert any(
        tag["Key"] == SOLUTION_TAG_KEY and tag["Value"] == SOLUTION_TAG_VALUE
        for tag in tags
    )
    # Check additional tags
    assert any(tag["Key"] == "Environment" and tag["Value"] == "Test" for tag in tags)
    assert any(tag["Key"] == "Owner" and tag["Value"] == "SecurityTeam" for tag in tags)


def test_solution_tag_constants():
    """Verify solution tag constants have correct values"""
    assert SOLUTION_TAG_KEY == "Solutions:SolutionName"
    assert SOLUTION_TAG_VALUE == "automated-security-response-on-aws"
