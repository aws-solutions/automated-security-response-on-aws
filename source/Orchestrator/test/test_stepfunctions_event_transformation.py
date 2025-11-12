# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json

from send_notifications import _transform_stepfunctions_failure_event


def test_transform_stepfunctions_failure_event():
    stepfunctions_event = {
        "version": "0",
        "id": "12345678-1234-1234-1234-123456789012",
        "detail-type": "Step Functions Execution Status Change",
        "source": "aws.states",
        "account": "123456789012",
        "time": "2024-01-01T12:00:00Z",
        "region": "us-east-1",
        "detail": {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:MyStateMachine:my-execution",
            "stateMachineArn": "arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine",
            "name": "my-execution",
            "status": "FAILED",
            "startDate": 1704110400000,
            "stopDate": 1704110460000,
            "input": json.dumps(
                {
                    "detail-type": "Security Hub Findings - Imported",
                    "detail": {
                        "findings": [
                            {
                                "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/test-finding",
                                "AwsAccountId": "123456789012",
                                "Region": "us-east-1",
                                "Resources": [
                                    {
                                        "Type": "AwsS3Bucket",
                                        "Id": "arn:aws:s3:::test-bucket",
                                    }
                                ],
                                "Severity": {"Label": "HIGH"},
                                "Compliance": {"SecurityControlId": "S3.1"},
                                "ProductFields": {
                                    "StandardsGuideArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
                                },
                            }
                        ],
                        "actionName": "CustomAction",
                    },
                }
            ),
            "cause": "Lambda function failed",
            "error": "LambdaError",
        },
    }

    result = _transform_stepfunctions_failure_event(stepfunctions_event)

    assert (
        result["Notification"]["Message"]
        == "Orchestrator execution failed: arn:aws:states:us-east-1:123456789012:execution:MyStateMachine:my-execution"
    )
    assert result["Notification"]["State"] == "FAILED"
    assert "Error: LambdaError" in result["Notification"]["Details"]
    assert "Cause: Lambda function failed" in result["Notification"]["Details"]
    assert (
        result["Notification"]["StepFunctionsExecutionId"]
        == "arn:aws:states:us-east-1:123456789012:execution:MyStateMachine:my-execution"
    )

    assert (
        result["Finding"]["Id"]
        == "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/test-finding"
    )
    assert result["Finding"]["AwsAccountId"] == "123456789012"
    assert result["Finding"]["Region"] == "us-east-1"

    assert result["EventType"] == "Security Hub Findings - Imported"
    assert result["CustomActionName"] == "CustomAction"
    assert result["AccountId"] == "123456789012"
    assert result["Region"] == "us-east-1"
    assert result["ControlId"] == "S3.1"


def test_transform_stepfunctions_timeout_event():
    stepfunctions_event = {
        "detail-type": "Step Functions Execution Status Change",
        "source": "aws.states",
        "detail": {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:MyStateMachine:timeout-execution",
            "name": "timeout-execution",
            "status": "TIMED_OUT",
            "input": json.dumps(
                {
                    "detail-type": "Security Hub Findings - Imported",
                    "detail": {
                        "findings": [
                            {
                                "Id": "test-finding-id",
                                "AwsAccountId": "123456789012",
                            }
                        ]
                    },
                }
            ),
            "cause": "Execution timed out",
            "error": "",
        },
    }

    result = _transform_stepfunctions_failure_event(stepfunctions_event)

    assert result["Notification"]["State"] == "TIMED_OUT"
    assert "Cause: Execution timed out" in result["Notification"]["Details"]


def test_transform_with_invalid_input():
    stepfunctions_event = {
        "detail-type": "Step Functions Execution Status Change",
        "source": "aws.states",
        "detail": {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:MyStateMachine:bad-input",
            "name": "bad-input",
            "status": "FAILED",
            "input": "invalid json {{{",
            "cause": "Parse error",
            "error": "ParseError",
        },
    }

    result = _transform_stepfunctions_failure_event(stepfunctions_event)

    # With invalid input, we now return a minimal valid finding instead of empty dict
    assert result["Finding"]["Id"] == "unknown"
    assert result["Notification"]["State"] == "FAILED"
    assert "Parse error" in result["Notification"]["Details"]
