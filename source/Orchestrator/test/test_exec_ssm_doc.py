# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any

import boto3
from botocore.stub import ANY, Stubber
from exec_ssm_doc import lambda_handler

from .test_orc_utils import create_lambda_context


def test_exec_runbook(mocker):
    """
    Verifies correct operation on success
    """
    step_input: dict[str, Any] = {
        "EventType": "Security Hub Findings - Custom Action",
        "Finding": {
            "SchemaVersion": "2018-10-08",
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1/finding/635ceb5d-3dfd-4458-804e-48a42cd723e4",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1",
            "AwsAccountId": "111111111111",
            "Types": [
                "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
            ],
            "FirstObservedAt": "2020-07-24T01:34:19.369Z",
            "LastObservedAt": "2021-02-18T13:45:30.638Z",
            "CreatedAt": "2020-07-24T01:34:19.369Z",
            "UpdatedAt": "2021-02-18T13:45:28.802Z",
            "Severity": {
                "Product": 0,
                "Label": "INFORMATIONAL",
                "Normalized": 0,
                "Original": "INFORMATIONAL",
            },
            "Title": "AutoScaling.1 Auto scaling groups associated with a load balancer should use load balancer health checks",
            "Description": "This control checks whether your Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For directions on how to fix this issue, please consult the AWS Security Hub Foundational Security Best Practices documentation.",
                    "Url": "https://docs.aws.amazon.com/console/securityhub/AutoScaling.1/remediation",
                }
            },
            "ProductFields": {
                "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0",
                "ControlId": "AutoScaling.1",
                "RecommendationUrl": "https://docs.aws.amazon.com/console/securityhub/AutoScaling.1/remediation",
                "RelatedAWSResources:0/name": "securityhub-autoscaling-group-elb-healthcheck-required-f986ecc9",
                "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
                "StandardsControlArn": "arn:aws:securityhub:us-east-1:111111111111:control/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1",
                "aws/securityhub/ProductName": "Security Hub",
                "aws/securityhub/CompanyName": "AWS",
                "aws/securityhub/annotation": "AWS Config evaluated your resources against the rule. The rule did not apply to the AWS resources in its scope, the specified resources were deleted, or the evaluation results were deleted.",
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1/finding/635ceb5d-3dfd-4458-804e-48a42cd723e4",
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": "arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:785df3481e1-cd66-435d-96de-d6ed5416defd:autoScalingGroupName/sharr-test-autoscaling-1",
                    "Partition": "aws",
                    "Region": "us-east-1",
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "StatusReasons": [
                    {
                        "ReasonCode": "CONFIG_EVALUATIONS_EMPTY",
                        "Description": "AWS Config evaluated your resources against the rule. The rule did not apply to the AWS resources in its scope, the specified resources were deleted, or the evaluation results were deleted.",
                    }
                ],
            },
            "WorkflowState": "NEW",
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        },
        "AutomationDocument": {
            "DocState": "ACTIVE",
            "SecurityStandardVersion": "1.0.0",
            "AccountId": "111111111111",
            "Message": 'Document Status is not "Active": unknown',
            "AutomationDocId": "SHARR-AFSBP_1.0.0_AutoScaling.1",
            "RemediationRole": "SO0111-Remediate-AFSBP-1.0.0-AutoScaling.1",
            "ControlId": "AutoScaling.1",
            "SecurityStandard": "AFSBP",
            "PlaybookEnabled": "True",
        },
        "SSMExecution": {
            "workflow_data": {"impact": "nondestructive", "approvalrequired": "false"}
        },
    }

    expected_result = {
        "executionid": "43374019-a309-4627-b8a2-c641e0140262",
        "logdata": [],
        "message": "AutoScaling.1 remediation was successfully invoked via AWS Systems Manager in account 111111111111: 43374019-a309-4627-b8a2-c641e0140262",
        "remediation_status": "",
        "status": "QUEUED",
    }

    account = "111111111111"
    step_input["AutomationDocument"]["AccountId"] = account
    iam_c = boto3.client("iam")
    iamc_stub = Stubber(iam_c)
    iamc_stub.add_client_error("get_role", "NoSuchEntity")
    iamc_stub.activate()

    ssm_c = boto3.client("ssm")
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        "start_automation_execution",
        {"AutomationExecutionId": "43374019-a309-4627-b8a2-c641e0140262"},
        {
            "DocumentName": "SHARR-AFSBP_1.0.0_AutoScaling.1",
            "Parameters": {"Finding": [ANY], "AutomationAssumeRole": [ANY]},
        },
    )

    ssmc_stub.activate()
    mocker.patch("exec_ssm_doc._get_ssm_client", return_value=ssm_c)
    mocker.patch("exec_ssm_doc._get_iam_client", return_value=iam_c)
    mocker.patch("layer.sechub_findings.ASRNotification.notify")

    response = lambda_handler(step_input, create_lambda_context())
    assert response["executionid"] == expected_result["executionid"]
    assert response["remediation_status"] == expected_result["remediation_status"]
    assert response["status"] == expected_result["status"]
    ssmc_stub.deactivate()
    iamc_stub.deactivate()


def test_exec_multi_service_runbook_with_finding_format(mocker):
    """
    Verifies that multi-service findings do NOT pass FindingFormat as an SSM parameter.
    The control runbooks (Inspector, GuardDuty, Macie) always receive OCSF and don't
    declare FindingFormat as an input — passing it causes InvalidAutomationExecutionParametersException.
    """
    step_input: dict[str, Any] = {
        "EventType": "Security Hub Findings - Imported",
        "Finding": {
            "class_uid": 2002,
            "class_name": "Vulnerability Finding",
            "cloud": {
                "account": {"uid": "111111111111"},
                "region": "us-east-1",
                "provider": "AWS",
            },
            "resources": [
                {
                    "uid": "arn:aws:ec2:us-east-1:111111111111:instance/i-1234567890abcdef0",
                    "region": "us-east-1",
                    "type": "AwsEc2Instance",
                }
            ],
        },
        "AutomationDocument": {
            "DocState": "ACTIVE",
            "SecurityStandardVersion": "4.0.0",
            "AccountId": "111111111111",
            "Message": "",
            "AutomationDocId": "ASR-Inspector.InstanceVulnerability",
            "RemediationRole": "SO0111-ASR-Orchestrator-Member",
            "ControlId": "Inspector.InstanceVulnerability",
            "SecurityStandard": "MultiService",
            "ResourceRegion": "us-east-1",
        },
        "Detail": {
            "findingFormat": "OCSF",
            "remediationId": "Inspector.InstanceVulnerability",
            "findingType": "multiService",
        },
    }

    iam_c = boto3.client("iam")
    iamc_stub = Stubber(iam_c)
    iamc_stub.add_client_error("get_role", "NoSuchEntity")
    iamc_stub.activate()

    ssm_c = boto3.client("ssm")
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        "start_automation_execution",
        {"AutomationExecutionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
        {
            "DocumentName": "ASR-Inspector.InstanceVulnerability",
            "Parameters": {
                "Finding": [ANY],
                "AutomationAssumeRole": [ANY],
                # No FindingFormat — control runbooks don't declare it as an input
            },
        },
    )
    ssmc_stub.activate()
    mocker.patch("exec_ssm_doc._get_ssm_client", return_value=ssm_c)
    mocker.patch("exec_ssm_doc._get_iam_client", return_value=iam_c)
    mocker.patch("layer.sechub_findings.ASRNotification.notify")

    response = lambda_handler(step_input, create_lambda_context())
    assert response["status"] == "QUEUED"
    assert response["executionid"] == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    ssmc_stub.deactivate()
    iamc_stub.deactivate()


def test_exec_config_finding_no_finding_format(mocker):
    """
    Verifies that existing Config findings without remediationId do NOT pass FindingFormat.
    """
    step_input: dict[str, Any] = {
        "EventType": "Security Hub Findings - Custom Action",
        "Finding": {
            "SchemaVersion": "2018-10-08",
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1/finding/test",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1",
            "AwsAccountId": "111111111111",
            "ProductFields": {
                "aws/securityhub/ProductName": "Security Hub",
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": "arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:test",
                    "Partition": "aws",
                    "Region": "us-east-1",
                }
            ],
            "Workflow": {"Status": "NEW"},
        },
        "AutomationDocument": {
            "DocState": "ACTIVE",
            "SecurityStandardVersion": "1.0.0",
            "AccountId": "111111111111",
            "Message": "",
            "AutomationDocId": "ASR-AFSBP_1.0.0_AutoScaling.1",
            "RemediationRole": "SO0111-Remediate-AFSBP-1.0.0-AutoScaling.1",
            "ControlId": "AutoScaling.1",
            "SecurityStandard": "AFSBP",
            "ResourceRegion": "us-east-1",
        },
        "Detail": {
            "findingFormat": "ASFF",
            "remediationId": "AutoScaling.1",
            "findingType": "securityControl",
        },
    }

    iam_c = boto3.client("iam")
    iamc_stub = Stubber(iam_c)
    iamc_stub.add_client_error("get_role", "NoSuchEntity")
    iamc_stub.activate()

    ssm_c = boto3.client("ssm")
    ssmc_stub = Stubber(ssm_c)
    # Note: No FindingFormat parameter expected for Config findings
    ssmc_stub.add_response(
        "start_automation_execution",
        {"AutomationExecutionId": "b2c3d4e5-f6a7-8901-bcde-f12345678901"},
        {
            "DocumentName": "ASR-AFSBP_1.0.0_AutoScaling.1",
            "Parameters": {
                "Finding": [ANY],
                "AutomationAssumeRole": [ANY],
            },
        },
    )
    ssmc_stub.activate()
    mocker.patch("exec_ssm_doc._get_ssm_client", return_value=ssm_c)
    mocker.patch("exec_ssm_doc._get_iam_client", return_value=iam_c)
    mocker.patch("layer.sechub_findings.ASRNotification.notify")

    response = lambda_handler(step_input, create_lambda_context())
    assert response["status"] == "QUEUED"
    assert response["executionid"] == "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    ssmc_stub.deactivate()
    iamc_stub.deactivate()


def test_exec_invalid_finding_format_defaults_to_asff(mocker):
    """Test that multi-service findings with any findingFormat still don't pass FindingFormat to SSM.
    The control runbooks don't declare FindingFormat as an input parameter."""
    step_input: dict[str, Any] = {
        "EventType": "Security Hub Findings - Imported",
        "Finding": {
            "class_uid": 2002,
            "cloud": {"account": {"uid": "111111111111"}, "region": "us-east-1"},
            "resources": [
                {
                    "uid": "arn:aws:ec2:us-east-1:111111111111:instance/i-abc",
                    "region": "us-east-1",
                }
            ],
        },
        "AutomationDocument": {
            "DocState": "ACTIVE",
            "SecurityStandardVersion": "4.0.0",
            "AccountId": "111111111111",
            "Message": "",
            "AutomationDocId": "ASR-Inspector.InstanceVulnerability",
            "RemediationRole": "SO0111-ASR-Orchestrator-Member",
            "ControlId": "Inspector.InstanceVulnerability",
            "SecurityStandard": "MultiService",
            "ResourceRegion": "us-east-1",
        },
        "Detail": {
            "findingFormat": "XML",
            "remediationId": "Inspector.InstanceVulnerability",
            "findingType": "multiService",
        },
    }

    iam_c = boto3.client("iam")
    iamc_stub = Stubber(iam_c)
    iamc_stub.add_client_error("get_role", "NoSuchEntity")
    iamc_stub.activate()

    ssm_c = boto3.client("ssm")
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        "start_automation_execution",
        {"AutomationExecutionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
        {
            "DocumentName": "ASR-Inspector.InstanceVulnerability",
            "Parameters": {
                "Finding": [ANY],
                "AutomationAssumeRole": [ANY],
                # No FindingFormat — not passed regardless of findingFormat value
            },
        },
    )
    ssmc_stub.activate()
    mocker.patch("exec_ssm_doc._get_ssm_client", return_value=ssm_c)
    mocker.patch("exec_ssm_doc._get_iam_client", return_value=iam_c)
    mocker.patch("layer.sechub_findings.ASRNotification.notify")

    response = lambda_handler(step_input, create_lambda_context())
    assert response["status"] == "QUEUED"
    ssmc_stub.deactivate()
    iamc_stub.deactivate()


def _guardduty_step_input(**overrides: Any) -> dict[str, Any]:
    """Factory for GuardDuty API-action step inputs. Pass keyword args to override top-level keys."""
    base: dict[str, Any] = {
        "EventType": "Security Hub Findings - API Action",
        "Finding": {
            "SchemaVersion": "2018-10-08",
            "Id": "arn:aws:guardduty:us-east-1:111111111111:detector/test/finding/abc",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
            "GeneratorId": "guardduty",
            "AwsAccountId": "111111111111",
            "Types": ["TTPs/Initial Access/UnauthorizedAccess:IAMUser"],
            "CreatedAt": "2024-01-01T00:00:00Z",
            "UpdatedAt": "2024-01-01T00:00:00Z",
            "Severity": {"Label": "HIGH", "Normalized": 70},
            "Title": "GuardDuty IAM User finding",
            "Description": "Compromised IAM credentials",
            "Resources": [
                {
                    "Type": "AwsIamAccessKey",
                    "Id": "arn:aws:iam::111111111111:user/test-user",
                    "Region": "us-east-1",
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "SecurityControlId": "GuardDuty.IAMUser",
            },
            "Region": "us-east-1",
        },
        "AutomationDocument": {
            "DocState": "ACTIVE",
            "SecurityStandardVersion": "4.0.0",
            "AccountId": "111111111111",
            "Message": "",
            "AutomationDocId": "ASR-GuardDuty.IAMUser",
            "RemediationRole": "SO0111-ASR-Orchestrator-Member",
            "ControlId": "GuardDuty.IAMUser",
            "SecurityStandard": "MultiService",
            "ResourceRegion": "us-east-1",
        },
    }
    base.update(overrides)
    return base


def test_exec_runbook_with_doc_parameters_passes_action_to_ssm(mocker):
    """
    Verifies that Action=Restore from docParameters is forwarded to the SSM document.
    The Stubber enforces the exact Parameters dict — if Action is missing or wrong,
    the Stubber raises an assertion error, making this the actual verification.
    """
    step_input = _guardduty_step_input(Detail={"docParameters": {"Action": "Restore"}})

    iam_client = boto3.client("iam")
    iam_stub = Stubber(iam_client)
    iam_stub.add_client_error("get_role", "NoSuchEntity")
    iam_stub.activate()

    ssm_client = boto3.client("ssm")
    ssm_stub = Stubber(ssm_client)
    ssm_stub.add_response(
        "start_automation_execution",
        {"AutomationExecutionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
        {
            "DocumentName": "ASR-GuardDuty.IAMUser",
            "Parameters": {
                "Finding": [ANY],
                "AutomationAssumeRole": [ANY],
                "Action": [
                    "Restore"
                ],  # Stubber rejects the call if Action is absent or wrong
            },
        },
    )
    ssm_stub.activate()
    mocker.patch("exec_ssm_doc._get_ssm_client", return_value=ssm_client)
    mocker.patch("exec_ssm_doc._get_iam_client", return_value=iam_client)
    mocker.patch("layer.sechub_findings.ASRNotification.notify")

    response = lambda_handler(step_input, create_lambda_context())

    assert response["status"] == "QUEUED"
    ssm_stub.deactivate()
    iam_stub.deactivate()


def test_exec_runbook_rejects_unknown_doc_parameters(mocker):
    """
    Verifies that unknown docParameters are rejected with a structured ERROR response.
    Only allowlisted parameter names (e.g. "Action") may be passed through
    to prevent overriding critical SSM parameters like Finding or AutomationAssumeRole.
    """
    step_input = _guardduty_step_input(
        Detail={
            "docParameters": {"AutomationAssumeRole": "arn:aws:iam::evil:role/attacker"}
        }
    )

    iam_client = boto3.client("iam")
    iam_stub = Stubber(iam_client)
    iam_stub.add_client_error("get_role", "NoSuchEntity")
    iam_stub.activate()

    mocker.patch("exec_ssm_doc._get_ssm_client", return_value=boto3.client("ssm"))
    mocker.patch("exec_ssm_doc._get_iam_client", return_value=iam_client)
    mocker.patch("layer.sechub_findings.ASRNotification.notify")

    response = lambda_handler(step_input, create_lambda_context())

    assert response["status"] == "ERROR"
    assert "Unsupported docParameter" in response["message"]
    iam_stub.deactivate()
