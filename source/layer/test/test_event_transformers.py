# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from layer.event_transformers import (
    Event,
    add_optional_finding_fields,
    extract_account_id,
    extract_region,
    extract_resource_owner_account,
    extract_resources,
    extract_severity,
    extract_stepfunctions_execution_id,
    is_notified_workflow,
    is_resolved_item,
    parse_orchestrator_input,
    resolve_finding_account_id,
    transform_stepfunctions_failure_event,
)


def test_extract_stepfunctions_execution_id_success():
    # ARRANGE
    event: Event = {
        "Notification": {
            "Message": "test",
            "State": "SUCCESS",
            "StepFunctionsExecutionId": "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution",
        },
        "Finding": {"Id": "test-id"},
    }

    # ACT
    result = extract_stepfunctions_execution_id(event)

    # ASSERT
    assert (
        result
        == "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution"
    )


def test_extract_stepfunctions_execution_id_missing():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
    }

    # ACT
    result = extract_stepfunctions_execution_id(event)

    # ASSERT
    assert result == "unknown"


def test_is_notified_workflow_true():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id", "Workflow": {"Status": "NOTIFIED"}},
    }

    # ACT
    result = is_notified_workflow(event)

    # ASSERT
    assert result is True


def test_is_notified_workflow_with_event_type():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id", "Workflow": {"Status": "NOTIFIED"}},
        "EventType": "Security Hub Findings - Custom Action",
    }

    # ACT
    result = is_notified_workflow(event)

    # ASSERT
    assert result is False


def test_is_notified_workflow_false():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id", "Workflow": {"Status": "NEW"}},
    }

    # ACT
    result = is_notified_workflow(event)

    # ASSERT
    assert result is False


def test_is_resolved_item_true():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "NOT_NEW"},
        "Finding": {"Id": "test-id", "Workflow": {"Status": "RESOLVED"}},
    }

    # ACT
    result = is_resolved_item(event)

    # ASSERT
    assert result is True


def test_is_resolved_item_false():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id", "Workflow": {"Status": "RESOLVED"}},
    }

    # ACT
    result = is_resolved_item(event)

    # ASSERT
    assert result is False


def test_parse_orchestrator_input_valid():
    # ARRANGE
    input_str = '{"detail": {"findings": [{"Id": "test-id"}]}}'

    # ACT
    result = parse_orchestrator_input(input_str)

    # ASSERT
    assert result == {"detail": {"findings": [{"Id": "test-id"}]}}


def test_parse_orchestrator_input_invalid():
    # ARRANGE
    input_str = "invalid json {{"

    # ACT
    result = parse_orchestrator_input(input_str)

    # ASSERT
    assert result == {}


def test_add_optional_finding_fields_complete():
    # ARRANGE
    transformed_event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
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

    # ACT
    add_optional_finding_fields(transformed_event, finding_data)

    # ASSERT
    assert transformed_event["AccountId"] == "123456789012"
    assert transformed_event["Region"] == "us-east-1"
    assert transformed_event["Resources"] == [{"Id": "i-123", "Type": "AwsEc2Instance"}]
    assert transformed_event["Severity"] == {"Label": "HIGH"}
    assert transformed_event["SecurityStandard"] == "arn:aws:securityhub:::ruleset/cis"
    assert transformed_event["ControlId"] == "EC2.1"


def test_add_optional_finding_fields_partial():
    # ARRANGE
    transformed_event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
    }

    finding_data = {"AwsAccountId": "123456789012", "Region": "us-west-2"}

    # ACT
    add_optional_finding_fields(transformed_event, finding_data)

    # ASSERT
    assert transformed_event["AccountId"] == "123456789012"
    assert transformed_event["Region"] == "us-west-2"
    assert "Resources" not in transformed_event
    assert "SecurityStandard" not in transformed_event


def test_transform_stepfunctions_failure_event_complete():
    # ARRANGE
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

    # ACT
    result = transform_stepfunctions_failure_event(raw_event)

    # ASSERT
    assert result["Notification"]["State"] == "FAILED"
    assert "test-execution" in result["Notification"]["Message"]
    assert "LambdaError" in result["Notification"]["Details"]
    assert result["Finding"]["Id"] == "test-finding-id"
    assert result["AccountId"] == "123456789012"
    assert result["CustomActionName"] == "CustomAction"


def test_transform_stepfunctions_failure_event_minimal():
    # ARRANGE
    raw_event = {
        "detail": {
            "executionArn": "arn:aws:states:us-east-1:123456789012:execution:TestStateMachine:test-execution",
            "status": "TIMEOUT",
        }
    }

    # ACT
    result = transform_stepfunctions_failure_event(raw_event)

    # ASSERT
    assert result["Notification"]["State"] == "TIMEOUT"
    assert result["Finding"]["Id"] == "unknown"
    assert result["Finding"]["Title"] == "Step Functions Execution Failure"


def test_transform_stepfunctions_failure_event_exception():
    # ARRANGE
    raw_event = None

    # ACT
    result = transform_stepfunctions_failure_event(raw_event)  # type: ignore[arg-type]

    # ASSERT
    assert result["Notification"]["State"] == "FAILED"
    assert "Failed to transform" in result["Notification"]["Message"]
    assert result["EventType"] == "Error"


def test_extract_account_id_from_root():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
        "AccountId": "123456789012",
    }

    # ACT
    result = extract_account_id(event)

    # ASSERT
    assert result == "123456789012"


def test_extract_account_id_from_finding():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id", "AwsAccountId": "987654321098"},
    }

    # ACT
    result = extract_account_id(event)

    # ASSERT
    assert result == "987654321098"


def test_extract_account_id_from_ssm_execution():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
        "SSMExecution": {"Account": "111111111111"},
    }

    # ACT
    result = extract_account_id(event)

    # ASSERT
    assert result == "111111111111"


def test_extract_account_id_empty():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
    }

    # ACT
    result = extract_account_id(event)

    # ASSERT
    assert result == ""


def test_extract_resource_owner_account_present():
    # ARRANGE: IAM Access Analyzer finding carrying the resource-owner account
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {
            "Id": "test-id",
            "ProductFields": {"ResourceOwnerAccount": "222222222222"},
        },
    }

    # ACT
    result = extract_resource_owner_account(event)

    # ASSERT
    assert result == "222222222222"


def test_extract_resource_owner_account_absent():
    # ARRANGE: no ProductFields at all
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
    }

    # ACT
    result = extract_resource_owner_account(event)

    # ASSERT
    assert result == ""


def test_resolve_finding_account_id_prefers_resource_owner_account():
    # ARRANGE: org-analyzer IAA finding (native access-analyzer ARN) where
    # AccountId/AwsAccountId (admin) differs from the resource owner
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "AccountId": "111111111111",
        "Finding": {
            "Id": "arn:aws:access-analyzer:us-east-1:111111111111:analyzer/org/arn:aws:kms:us-east-1:222222222222:key/abc",
            "AwsAccountId": "111111111111",
            "ProductFields": {"ResourceOwnerAccount": "222222222222"},
        },
    }

    # ACT
    result = resolve_finding_account_id(event)

    # ASSERT: the resource-owner account wins over the administrator account
    assert result == "222222222222"


def test_resolve_finding_account_id_ignores_resource_owner_account_for_non_access_analyzer():
    # ARRANGE: a non-Access-Analyzer finding that nonetheless carries
    # ProductFields.ResourceOwnerAccount must not have its account overridden
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {
            "Id": "arn:aws:securityhub:us-east-1:987654321098:security-control/S3.1/finding/abc",
            "AwsAccountId": "987654321098",
            "ProductFields": {"ResourceOwnerAccount": "222222222222"},
        },
    }

    # ACT
    result = resolve_finding_account_id(event)

    # ASSERT: falls back to AwsAccountId, ignoring ResourceOwnerAccount
    assert result == "987654321098"


def test_resolve_finding_account_id_falls_back_to_account_id():
    # ARRANGE: no ResourceOwnerAccount, so the standard account resolution applies
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id", "AwsAccountId": "987654321098"},
    }

    # ACT
    result = resolve_finding_account_id(event)

    # ASSERT
    assert result == "987654321098"


def test_resolve_finding_account_id_falls_back_for_non_12_digit_resource_owner_account():
    # ARRANGE: an Access Analyzer finding whose ResourceOwnerAccount is crafted/malformed.
    # The history-write path falls back to AwsAccountId (unlike the findings-table
    # write, which fails closed) since the remediation has already run.
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {
            "Id": "arn:aws:access-analyzer:us-east-1:111111111111:analyzer/org/arn:aws:kms:us-east-1:222222222222:key/abc",
            "AwsAccountId": "111111111111",
            "ProductFields": {"ResourceOwnerAccount": "not-an-account"},
        },
    }

    # ACT
    result = resolve_finding_account_id(event)

    # ASSERT: the malformed value is rejected and AwsAccountId is used
    assert result == "111111111111"


def test_extract_region_from_root():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
        "Region": "us-east-1",
    }

    # ACT
    result = extract_region(event)

    # ASSERT
    assert result == "us-east-1"


def test_extract_region_from_finding():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id", "Region": "us-west-2"},
    }

    # ACT
    result = extract_region(event)

    # ASSERT
    assert result == "us-west-2"


def test_extract_region_from_ssm_execution():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
        "SSMExecution": {"Region": "eu-west-1"},
    }

    # ACT
    result = extract_region(event)

    # ASSERT
    assert result == "eu-west-1"


def test_extract_region_empty():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
    }

    # ACT
    result = extract_region(event)

    # ASSERT
    assert result == ""


def test_extract_severity_from_root():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
        "Severity": {"Label": "HIGH"},
    }

    # ACT
    result = extract_severity(event)

    # ASSERT
    assert result == "HIGH"


def test_extract_severity_from_finding():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id", "Severity": {"Label": "MEDIUM"}},
    }

    # ACT
    result = extract_severity(event)

    # ASSERT
    assert result == "MEDIUM"


def test_extract_severity_empty():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
    }

    # ACT
    result = extract_severity(event)

    # ASSERT
    assert result == ""


def test_extract_resources_from_root():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
        "Resources": [{"Id": "arn:aws:s3:::test-bucket", "Type": "AwsS3Bucket"}],
    }

    # ACT
    result = extract_resources(event)

    # ASSERT
    assert result["Id"] == "arn:aws:s3:::test-bucket"
    assert result["Type"] == "AwsS3Bucket"


def test_extract_resources_from_finding():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {
            "Id": "test-id",
            "Resources": [
                {
                    "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
                    "Type": "AwsEc2Instance",
                }
            ],
        },
    }

    # ACT
    result = extract_resources(event)

    # ASSERT
    assert (
        result["Id"]
        == "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
    )
    assert result["Type"] == "AwsEc2Instance"


def test_extract_resources_empty():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
    }

    # ACT
    result = extract_resources(event)

    # ASSERT
    assert result == {}


def test_extract_resources_dict_format():
    # ARRANGE
    event: Event = {
        "Notification": {"Message": "test", "State": "SUCCESS"},
        "Finding": {"Id": "test-id"},
        "Resources": {"Id": "arn:aws:s3:::test-bucket", "Type": "AwsS3Bucket"},
    }

    # ACT
    result = extract_resources(event)

    # ASSERT
    assert result["Id"] == "arn:aws:s3:::test-bucket"
    assert result["Type"] == "AwsS3Bucket"
