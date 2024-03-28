# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit Test: exec_ssm_doc.py
Run from /deployment/temp/source/Orchestrator after running build-s3-dist.sh
"""
from typing import Any

import boto3
from botocore.stub import ANY, Stubber
from exec_ssm_doc import lambda_handler


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
            "SecurityStandardSupported": "True",
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
    mocker.patch("sechub_findings.SHARRNotification.notify")

    response = lambda_handler(step_input, {})
    assert response["executionid"] == expected_result["executionid"]
    assert response["remediation_status"] == expected_result["remediation_status"]
    assert response["status"] == expected_result["status"]
    ssmc_stub.deactivate()
    iamc_stub.deactivate()
