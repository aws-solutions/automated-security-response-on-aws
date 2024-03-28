# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit Test: check_ssm_execution.py
Run from /deployment/temp/source/Orchestrator after running build-s3-dist.sh
"""
import os
from typing import Any

import boto3
import pytest
from botocore.stub import ANY, Stubber
from check_ssm_execution import AutomationExecution, lambda_handler
from layer.awsapi_cached_client import AWSCachedClient


def get_region():
    return os.getenv("AWS_DEFAULT_REGION")


test_event: Any = {
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
        "Message": "AutoScaling.1remediation was successfully invoked via AWS Systems Manager in account 111111111111: 43374019-a309-4627-b8a2-c641e0140262",
        "ExecId": "43374019-a309-4627-b8a2-c641e0140262",
        "ExecState": "SUCCESS",
        "Account": "111111111111",
        "Region": "us-east-1",
    },
    "Remediation": {
        "LogData": [],
        "RemediationState": "running",
        "ExecId": "43374019-a309-4627-b8a2-c641e0140262",
        "Message": "Waiting for completion",
        "AffectedObject": "",
        "ExecState": "InProgress",
    },
}

ssm_mocked_failed_response = {
    "AutomationExecutionMetadataList": [
        {
            "AutomationExecutionId": "43374019-a309-4627-b8a2-c641e0140262",
            "DocumentName": "SHARRRemediation-AFSBP_1.0.0_AutoScaling.1",
            "DocumentVersion": "1",
            "AutomationExecutionStatus": "Failed",
            "ExecutionStartTime": "2021-05-24T10:57:31.322000-04:00",
            "ExecutionEndTime": "2021-05-24T10:57:39.878000-04:00",
            "ExecutedBy": "arn:aws:sts::111111111111:assumed-role/SO0111-SHARR-Orchestrator-Member_us-east-1/sechub_admin",
            "LogFile": "",
            "Outputs": {
                "ParseInput.AffectedObject": [
                    "No output available yet because the step is not successfully executed"
                ],
                "Remediation.Output": [
                    "No output available yet because the step is not successfully executed"
                ],
            },
            "Mode": "Auto",
            "FailureMessage": "Step fails when it is Poll action status for completion. Traceback (most recent call last):\n  File \"/tmp/5a927c4c-3d51-4915-8d7e-82fc4c61e479-2021-05-24-14-57-35/customer_script.py\", line 4, in parse_event\n    my_control_id = event['expected_control_id']\n\nKeyError - 'expected_control_id'. Please refer to Automation Service Troubleshooting Guide for more diagnosis details.",
            "Targets": [],
            "ResolvedTargets": {"ParameterValues": [], "Truncated": False},
            "AutomationType": "Local",
        }
    ]
}
ssm_mocked_good_response = {
    "AutomationExecutionMetadataList": [
        {
            "AutomationExecutionId": "5f12697a-70a5-4a64-83e6-b7d429ec2b17",
            "DocumentName": "AWSConfigRemediation-EnableEbsEncryptionByDefault",
            "DocumentVersion": "1",
            "AutomationExecutionStatus": "Success",
            "ExecutionStartTime": "2021-05-06T15:16:14.162000-04:00",
            "ExecutionEndTime": "2021-05-06T15:16:25.732000-04:00",
            "ExecutedBy": "arn:aws:sts::111111111111:assumed-role/SO0111-Remediate-AFSBP-1.0.0-EC2.7_us-east-1/ced3db7c-7958-4225-82dc-0a607480554e",
            "LogFile": "",
            "Outputs": {
                "ModifyAccount.EnableEbsEncryptionByDefaultResponse": [
                    '{"EbsEncryptionByDefault":true,"ResponseMetadata":{"RequestId":"c45a9839-5a40-472e-ac83-d0058987948c","HTTPStatusCode":200,"HTTPHeaders":{"x-amzn-requestid":"c45a9839-5a40-472e-ac83-d0058987948c","cache-control":"no-cache, no-store","strict-transport-security":"max-age\\u003d31536000; includeSubDomains","content-type":"text/xml;charset\\u003dUTF-8","transfer-encoding":"chunked","vary":"accept-encoding","date":"Thu, 06 May 2021 19:16:14 GMT","server":"AmazonEC2"},"RetryAttempts":0}}'
                ]
            },
            "Mode": "Auto",
            "ParentAutomationExecutionId": "795cf453-c41a-48df-aace-fd68fdace188",
            "Targets": [],
            "ResolvedTargets": {"ParameterValues": [], "Truncated": False},
            "AutomationType": "Local",
        }
    ]
}


def test_failed_remediation(mocker):
    """
    Verifies correct operation when a child remediation fails
    """
    AWS = AWSCachedClient(get_region())
    account = "111111111111"
    test_event["AutomationDocument"]["AccountId"] = account
    ssm_c = AWS.get_connection("ssm")

    expected_result = {
        "affected_object": "No output available yet because the step is not successfully executed",
        "executionid": "43374019-a309-4627-b8a2-c641e0140262",
        "logdata": ANY,
        "remediation_status": "Failed",
        "status": "Failed",
        "message": "See Automation Execution output for details",
    }

    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response("get_parameter", {})
    ssmc_stub.add_response(
        "describe_automation_executions",
        ssm_mocked_failed_response,
        {
            "Filters": [
                {
                    "Key": "ExecutionId",
                    "Values": ["43374019-a309-4627-b8a2-c641e0140262"],
                }
            ]
        },
    )
    ssmc_stub.activate()
    mocker.patch("check_ssm_execution._get_ssm_client", return_value=ssm_c)

    response = lambda_handler(test_event, {})
    assert response == expected_result
    ssmc_stub.deactivate()


def test_successful_remediation(mocker):
    """
    Verifies correct operation for successful remediation
    """
    ssm_c = boto3.client("ssm")
    account = "111111111111"
    test_event["AutomationDocument"]["AccountId"] = account
    test_event["SSMExecution"]["ExecId"] = "5f12697a-70a5-4a64-83e6-b7d429ec2b17"

    expected_result = {
        "affected_object": "UNKNOWN",
        "executionid": "5f12697a-70a5-4a64-83e6-b7d429ec2b17",
        "logdata": "[]",
        "message": '{"ModifyAccount.EnableEbsEncryptionByDefaultResponse": ["{\\"EbsEncryptionByDefault\\":true,\\"ResponseMetadata\\":{\\"RequestId\\":\\"c45a9839-5a40-472e-ac83-d0058987948c\\",\\"HTTPStatusCode\\":200,\\"HTTPHeaders\\":{\\"x-amzn-requestid\\":\\"c45a9839-5a40-472e-ac83-d0058987948c\\",\\"cache-control\\":\\"no-cache, no-store\\",\\"strict-transport-security\\":\\"max-age\\\\u003d31536000; includeSubDomains\\",\\"content-type\\":\\"text/xml;charset\\\\u003dUTF-8\\",\\"transfer-encoding\\":\\"chunked\\",\\"vary\\":\\"accept-encoding\\",\\"date\\":\\"Thu, 06 May 2021 19:16:14 GMT\\",\\"server\\":\\"AmazonEC2\\"},\\"RetryAttempts\\":0}}"]}',
        "remediation_status": "Success",
        "status": "Success",
    }

    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "describe_automation_executions",
        ssm_mocked_good_response,
        {
            "Filters": [
                {
                    "Key": "ExecutionId",
                    "Values": ["5f12697a-70a5-4a64-83e6-b7d429ec2b17"],
                }
            ]
        },
    )
    ssmc_stub.activate()

    mocker.patch("check_ssm_execution._get_ssm_client", return_value=ssm_c)
    mocker.patch("check_ssm_execution.Metrics.send_metrics", return_value=False)
    mocker.patch(
        "check_ssm_execution.Metrics.get_metrics_from_finding", return_value=False
    )
    mocker.patch("check_ssm_execution.Metrics.__init__", return_value=None)

    response = lambda_handler(test_event, {})
    assert response == expected_result

    ssmc_stub.deactivate()


def test_execid_parsing_nonsharr(mocker):
    """
    Verifies correct operation for successful remediation
    """
    ssm_c = boto3.client("ssm")
    account = "111111111111"
    test_event["AutomationDocument"]["AccountId"] = account
    test_event["SSMExecution"]["ExecId"] = "5f12697a-70a5-4a64-83e6-b7d429ec2b17"

    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "describe_automation_executions",
        ssm_mocked_good_response,
        {
            "Filters": [
                {
                    "Key": "ExecutionId",
                    "Values": ["5f12697a-70a5-4a64-83e6-b7d429ec2b17"],
                }
            ]
        },
    )
    ssmc_stub.activate()

    mocker.patch("check_ssm_execution._get_ssm_client", return_value=ssm_c)

    automation_exec_info = AutomationExecution(
        test_event["SSMExecution"]["ExecId"], account, "foo-bar-baz", "us-east-1"
    )
    assert automation_exec_info.status == "Success"
    assert (
        automation_exec_info.outputs
        == ssm_mocked_good_response["AutomationExecutionMetadataList"][0]["Outputs"]
    )
    assert automation_exec_info.failure_message == ""
    assert automation_exec_info.account == account
    assert automation_exec_info.region == "us-east-1"


def test_execid_parsing_sharr(mocker):
    """
    Verifies correct operation for successful remediation
    """
    ssm_c = boto3.client("ssm")
    account = "111111111111"
    test_event["AutomationDocument"]["AccountId"] = account
    test_event["SSMExecution"]["ExecId"] = "795cf453-c41a-48df-aace-fd68fdace188"

    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "describe_automation_executions",
        ssm_mocked_good_response,
        {
            "Filters": [
                {
                    "Key": "ExecutionId",
                    "Values": ["795cf453-c41a-48df-aace-fd68fdace188"],
                }
            ]
        },
    )
    ssmc_stub.activate()

    mocker.patch("check_ssm_execution._get_ssm_client", return_value=ssm_c)

    automation_exec_info = AutomationExecution(
        test_event["SSMExecution"]["ExecId"], account, "foo-bar-baz", "us-east-1"
    )
    assert automation_exec_info.status == "Success"
    assert (
        automation_exec_info.outputs
        == ssm_mocked_good_response["AutomationExecutionMetadataList"][0]["Outputs"]
    )
    assert automation_exec_info.failure_message == ""
    assert automation_exec_info.account == account
    assert automation_exec_info.region == "us-east-1"

    ssmc_stub.deactivate()
    ssmc_stub.deactivate()


def test_missing_account_id(mocker):
    """
    Verifies that system exit occurs when an account ID is missing from event
    """
    ssm_c = boto3.client("ssm")
    test_event["SSMExecution"]["ExecId"] = "5f12697a-70a5-4a64-83e6-b7d429ec2b17"
    test_event["SSMExecution"]["Account"] = None

    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "describe_automation_executions",
        ssm_mocked_good_response,
        {
            "Filters": [
                {
                    "Key": "ExecutionId",
                    "Values": ["5f12697a-70a5-4a64-83e6-b7d429ec2b17"],
                }
            ]
        },
    )
    ssmc_stub.activate()

    mocker.patch("check_ssm_execution._get_ssm_client", return_value=ssm_c)
    mocker.patch("check_ssm_execution.Metrics.send_metrics", return_value=False)
    mocker.patch(
        "check_ssm_execution.Metrics.get_metrics_from_finding", return_value=False
    )
    mocker.patch("check_ssm_execution.Metrics.__init__", return_value=None)

    with pytest.raises(SystemExit) as response:
        lambda_handler(test_event, {})

    assert (
        response.value.code
        == "ERROR: missing remediation account information. SSMExecution missing region or account."
    )

    ssmc_stub.deactivate()


def test_missing_region(mocker):
    """
    Verifies that system exit occurs when region is missing
    """
    ssm_c = boto3.client("ssm")
    test_event["SSMExecution"]["ExecId"] = "5f12697a-70a5-4a64-83e6-b7d429ec2b17"
    test_event["SSMExecution"]["Region"] = None

    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "describe_automation_executions",
        ssm_mocked_good_response,
        {
            "Filters": [
                {
                    "Key": "ExecutionId",
                    "Values": ["5f12697a-70a5-4a64-83e6-b7d429ec2b17"],
                }
            ]
        },
    )
    ssmc_stub.activate()

    mocker.patch("check_ssm_execution._get_ssm_client", return_value=ssm_c)
    mocker.patch("check_ssm_execution.Metrics.send_metrics", return_value=False)
    mocker.patch(
        "check_ssm_execution.Metrics.get_metrics_from_finding", return_value=False
    )
    mocker.patch("check_ssm_execution.Metrics.__init__", return_value=None)

    with pytest.raises(SystemExit) as response:
        lambda_handler(test_event, {})

    assert (
        response.value.code
        == "ERROR: missing remediation account information. SSMExecution missing region or account."
    )

    ssmc_stub.deactivate()
