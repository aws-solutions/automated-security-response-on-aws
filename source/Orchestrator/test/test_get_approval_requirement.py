# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit Test: exec_ssm_doc.py
Run from /deployment/temp/source/Orchestrator after running build-s3-dist.sh
"""
import os

import pytest
from botocore.stub import Stubber
from get_approval_requirement import lambda_handler
from layer.awsapi_cached_client import AWSCachedClient


def get_region():
    return os.getenv("AWS_DEFAULT_REGION")


@pytest.fixture(autouse=True)
def mock_get_running_account(mocker):
    mocker.patch(
        "get_approval_requirement.get_running_account", return_value="111111111111"
    )


def step_input():
    return {
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
            "AutomationDocId": "ASR-AFSBP_1.0.0_AutoScaling.1",
            "RemediationRole": "SO0111-Remediate-AFSBP-1.0.0-AutoScaling.1",
            "ControlId": "AutoScaling.1",
            "SecurityStandard": "AFSBP",
            "SecurityStandardSupported": "True",
        },
    }


def step_input_config():
    return {
        "EventType": "Security Hub Findings - Custom Action",
        "Finding": {
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/config",
            "Types": ["Software and Configuration Checks"],
            "Description": "This finding is created for a resource compliance change for config rule: test-config-rule-policy",
            "SchemaVersion": "2018-10-08",
            "Compliance": {"Status": "FAILED"},
            "GeneratorId": "arn:aws:config:us-east-1:111111111111:config-rule/config-rule-k5r9xw",
            "CreatedAt": "2023-10-26T20:26:06.736Z",
            "RecordState": "ACTIVE",
            "Title": "ConfigRuleName",
            "Workflow": {"Status": "NOTIFIED"},
            "Severity": {"Normalized": 40, "Label": "MEDIUM"},
            "UpdatedAt": "2023-10-26T20:26:06.736Z",
            "CompanyName": "AWS",
            "FindingProviderFields": {
                "Types": ["Software and Configuration Checks"],
                "Severity": {"Normalized": 40, "Label": "MEDIUM"},
            },
            "WorkflowState": "NEW",
            "ProductFields": {
                "aws/securityhub/ProductName": "Config",
                "aws/securityhub/CompanyName": "AWS",
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/config/arn:aws:config:us-east-1:111111111111:config-rule/config-rule-k5r9xw/finding/3027db7f9b58b5ff20354bc654f0ad706cf70d1a",
                "aws/config/ConfigRuleArn": "arn:aws:config:us-east-1:111111111111:config-rule/config-rule-k5r9xw",
                "aws/config/ConfigRuleName": "test-config-rule-policy",
                "aws/config/ConfigComplianceType": "NON_COMPLIANT",
            },
            "AwsAccountId": "111111111111",
            "Region": "us-east-1",
            "Id": "arn:aws:config:us-east-1:111111111111:config-rule/config-rule-k5r9xw/finding/3027db7f9b58b5ff20354bc654f0ad706cf70d1a",
            "Resources": [
                {
                    "Partition": "aws",
                    "Type": "Other",
                    "Region": "us-east-1",
                    "Id": "AWS::::Account:111111111111",
                }
            ],
        },
    }


def test_get_approval_req(mocker):
    """
    Verifies that it returns the fanout runbook name
    """
    os.environ["WORKFLOW_RUNBOOK"] = "ASR-RunWorkflow"
    os.environ["WORKFLOW_RUNBOOK_ACCOUNT"] = "member"
    expected_result = {
        "workflowdoc": "ASR-RunWorkflow",
        "workflowaccount": "111111111111",
        "workflowrole": "",
        "workflow_data": {"impact": "nondestructive", "approvalrequired": "false"},
    }

    AWS = AWSCachedClient(get_region())
    account = "111111111111"
    step_input()["AutomationDocument"]["AccountId"] = account

    ssm_c = AWS.get_connection("ssm")
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "DataType": "text",
            }
        },
        {
            "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname"
        },
    )
    ssmc_stub.add_client_error("get_parameter", "ParameterNotFound")
    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:44.632000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "DataType": "text",
            }
        },
    )
    ssmc_stub.add_response(
        "describe_document",
        {
            "Document": {
                "Hash": "be480c5a8771035918c439a0c76e1471306a699b7f275fe7e0bea70903dc569a",
                "HashType": "Sha256",
                "Name": "ASR-RunWorkflow",
                "Owner": "111111111111",
                "CreatedDate": "2021-05-13T09:01:20.399000-04:00",
                "Status": "Active",
                "DocumentVersion": "1",
                "Description": "### Document Name - ASR-RunWorkflow",
                "Parameters": [
                    {
                        "Name": "AutomationAssumeRole",
                        "Type": "String",
                        "Description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
                        "DefaultValue": "",
                    },
                    {
                        "Name": "Finding",
                        "Type": "StringMap",
                        "Description": "The input from Step function for ASG1 finding",
                    },
                ],
                "PlatformTypes": ["Windows", "Linux", "MacOS"],
                "DocumentType": "Automation",
                "SchemaVersion": "0.3",
                "LatestVersion": "1",
                "DefaultVersion": "1",
                "DocumentFormat": "JSON",
                "Tags": [],
            }
        },
        {"Name": "ASR-RunWorkflow"},
    )

    ssmc_stub.activate()
    mocker.patch("get_approval_requirement._get_ssm_client", return_value=ssm_c)

    response = lambda_handler(step_input(), {})

    assert response["workflow_data"] == expected_result["workflow_data"]
    assert response["workflowdoc"] == expected_result["workflowdoc"]
    assert response["workflowaccount"] == expected_result["workflowaccount"]
    assert response["workflowrole"] == expected_result["workflowrole"]

    ssmc_stub.deactivate()


def test_get_approval_req_no_fanout(mocker):
    """
    Verifies that it does not return workflow_status at all
    """
    os.environ["WORKFLOW_RUNBOOK"] = ""
    expected_result = {
        "workflowdoc": "",
        "workflowaccount": "",
        "workflowrole": "",
        "workflow_data": {"impact": "nondestructive", "approvalrequired": "false"},
    }

    AWS = AWSCachedClient(get_region())
    account = "111111111111"
    step_input()["AutomationDocument"]["AccountId"] = account

    ssm_c = AWS.get_connection("ssm")
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "DataType": "text",
            }
        },
        {
            "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname"
        },
    )
    ssmc_stub.add_client_error("get_parameter", "ParameterNotFound")
    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:44.632000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "DataType": "text",
            }
        },
    )
    ssmc_stub.add_response(
        "describe_document",
        {
            "Document": {
                "Hash": "be480c5a8771035918c439a0c76e1471306a699b7f275fe7e0bea70903dc569a",
                "HashType": "Sha256",
                "Name": "ASR-RunWorkflow",
                "Owner": "111111111111",
                "CreatedDate": "2021-05-13T09:01:20.399000-04:00",
                "Status": "Active",
                "DocumentVersion": "1",
                "Description": "### Document Name - ASR-RunWorkflow",
                "Parameters": [
                    {
                        "Name": "AutomationAssumeRole",
                        "Type": "String",
                        "Description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
                        "DefaultValue": "",
                    },
                    {
                        "Name": "Finding",
                        "Type": "StringMap",
                        "Description": "The input from Step function for ASG1 finding",
                    },
                ],
                "PlatformTypes": ["Windows", "Linux", "MacOS"],
                "DocumentType": "Automation",
                "SchemaVersion": "0.3",
                "LatestVersion": "1",
                "DefaultVersion": "1",
                "DocumentFormat": "JSON",
                "Tags": [],
            }
        },
        {"Name": "ASR-RunWorkflow"},
    )

    ssmc_stub.activate()
    mocker.patch("get_approval_requirement._get_ssm_client", return_value=ssm_c)

    response = lambda_handler(step_input(), {})
    print(response)

    assert response["workflow_data"] == expected_result["workflow_data"]
    assert response["workflowdoc"] == expected_result["workflowdoc"]
    assert response["workflowaccount"] == expected_result["workflowaccount"]
    assert response["workflowrole"] == expected_result["workflowrole"]

    ssmc_stub.deactivate()


# ==================================================================================
def test_workflow_in_admin(mocker):
    """
    Verifies that it returns the fanout runbook name
    """
    os.environ["WORKFLOW_RUNBOOK"] = "ASR-RunWorkflow"
    os.environ["WORKFLOW_RUNBOOK_ACCOUNT"] = "admin"
    os.environ["WORKFLOW_RUNBOOK_ROLE"] = "someotheriamrole"
    expected_result = {
        "workflowdoc": "ASR-RunWorkflow",
        "workflowaccount": "111111111111",
        "workflowrole": "someotheriamrole",
        "workflow_data": {"impact": "nondestructive", "approvalrequired": "false"},
    }

    AWS = AWSCachedClient(get_region())
    account = "111111111111"
    step_input()["AutomationDocument"]["AccountId"] = account

    ssm_c = AWS.get_connection("ssm")
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "DataType": "text",
            }
        },
        {
            "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname"
        },
    )
    ssmc_stub.add_client_error("get_parameter", "ParameterNotFound")
    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:44.632000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "DataType": "text",
            }
        },
    )
    ssmc_stub.add_response(
        "describe_document",
        {
            "Document": {
                "Hash": "be480c5a8771035918c439a0c76e1471306a699b7f275fe7e0bea70903dc569a",
                "HashType": "Sha256",
                "Name": "ASR-RunWorkflow",
                "Owner": "111111111111",
                "CreatedDate": "2021-05-13T09:01:20.399000-04:00",
                "Status": "Active",
                "DocumentVersion": "1",
                "Description": "### Document Name - ASR-RunWorkflow",
                "Parameters": [
                    {
                        "Name": "AutomationAssumeRole",
                        "Type": "String",
                        "Description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
                        "DefaultValue": "",
                    },
                    {
                        "Name": "Finding",
                        "Type": "StringMap",
                        "Description": "The input from Step function for ASG1 finding",
                    },
                ],
                "PlatformTypes": ["Windows", "Linux", "MacOS"],
                "DocumentType": "Automation",
                "SchemaVersion": "0.3",
                "LatestVersion": "1",
                "DefaultVersion": "1",
                "DocumentFormat": "JSON",
                "Tags": [],
            }
        },
        {"Name": "ASR-RunWorkflow"},
    )

    ssmc_stub.activate()
    mocker.patch("get_approval_requirement._get_ssm_client", return_value=ssm_c)

    response = lambda_handler(step_input(), {})
    print(response)
    assert response["workflow_data"] == expected_result["workflow_data"]
    assert response["workflowdoc"] == expected_result["workflowdoc"]
    assert response["workflowaccount"] == expected_result["workflowaccount"]
    assert response["workflowrole"] == expected_result["workflowrole"]

    ssmc_stub.deactivate()


def test_get_approval_config(mocker):
    """
    Verifies that config runbooks defined are set as expected
    """
    os.environ["WORKFLOW_RUNBOOK"] = ""
    expected_result = {
        "workflowdoc": "ASR-TestConfigDoc",
        "workflowrole": "ASR-TestRole",
        "workflow_data": {
            "impact": "nondestructive",
            "approvalrequired": "false",
            "security_hub": "false",
        },
    }

    AWS = AWSCachedClient(get_region())

    ssm_c = AWS.get_connection("ssm")
    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/ConfigRuleName",
                "Type": "String",
                "Value": '{"RunbookName":"ASR-TestConfigDoc","RunbookRole":"ASR-TestRole"}',
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/ConfigRuleName",
                "DataType": "text",
            }
        },
        {"Name": "/Solutions/SO0111/ConfigRuleName"},
    )

    ssmc_stub.activate()
    mocker.patch("boto3.client", return_value=ssm_c)

    response = lambda_handler(step_input_config(), {})

    assert response["workflow_data"] == expected_result["workflow_data"]
    assert response["workflowdoc"] == expected_result["workflowdoc"]
    assert response["workflowrole"] == expected_result["workflowrole"]

    ssmc_stub.deactivate()


def test_get_approval_config_no_role(mocker):
    """
    Verifies that config runbooks with no roles defined are set as expected
    """
    os.environ["WORKFLOW_RUNBOOK"] = ""
    expected_result = {
        "workflowdoc": "ASR-TestConfigDoc",
        "workflowrole": "",
        "workflow_data": {
            "impact": "nondestructive",
            "approvalrequired": "false",
            "security_hub": "false",
        },
    }

    AWS = AWSCachedClient(get_region())

    ssm_c = AWS.get_connection("ssm")
    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/ConfigRuleName",
                "Type": "String",
                "Value": '{"RunbookName":"ASR-TestConfigDoc"}',
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/ConfigRuleName",
                "DataType": "text",
            }
        },
        {"Name": "/Solutions/SO0111/ConfigRuleName"},
    )

    ssmc_stub.activate()
    mocker.patch("boto3.client", return_value=ssm_c)

    response = lambda_handler(step_input_config(), {})

    assert response["workflow_data"] == expected_result["workflow_data"]
    assert response["workflowdoc"] == expected_result["workflowdoc"]
    assert response["workflowrole"] == expected_result["workflowrole"]

    ssmc_stub.deactivate()


def test_get_approval_health(mocker):
    """
    Verifies that health runbooks get run as expected
    """
    os.environ["WORKFLOW_RUNBOOK"] = ""
    expected_result = {
        "workflowdoc": "ASR-TestConfigDoc",
        "workflowrole": "ASR-TestRole",
        "workflow_data": {
            "impact": "nondestructive",
            "approvalrequired": "false",
            "security_hub": "false",
        },
    }

    AWS = AWSCachedClient(get_region())
    step_input_health = step_input_config()
    step_input_health["Finding"]["ProductFields"][
        "aws/securityhub/ProductName"
    ] = "Health"
    step_input_health["Finding"]["GeneratorId"] = "HealthRuleName"

    ssm_c = AWS.get_connection("ssm")
    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/HealthRuleName",
                "Type": "String",
                "Value": '{"RunbookName":"ASR-TestConfigDoc","RunbookRole":"ASR-TestRole"}',
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/HealthRuleName",
                "DataType": "text",
            }
        },
        {"Name": "/Solutions/SO0111/HealthRuleName"},
    )

    ssmc_stub.activate()
    mocker.patch("boto3.client", return_value=ssm_c)
    response = lambda_handler(step_input_health, {})

    assert response["workflow_data"] == expected_result["workflow_data"]
    assert response["workflowdoc"] == expected_result["workflowdoc"]
    assert response["workflowrole"] == expected_result["workflowrole"]

    ssmc_stub.deactivate()


def test_get_approval_guardduty(mocker):
    """
    Verifies that it returns the fanout runbook name
    """
    os.environ["WORKFLOW_RUNBOOK"] = ""
    expected_result = {
        "workflowdoc": "ASR-TestConfigDoc",
        "workflowrole": "ASR-TestRole",
        "workflow_data": {
            "impact": "nondestructive",
            "approvalrequired": "false",
            "security_hub": "false",
        },
    }

    AWS = AWSCachedClient(get_region())
    step_input_guardduty = step_input_config()
    step_input_guardduty["Finding"]["ProductFields"][
        "aws/securityhub/ProductName"
    ] = "GuardDuty"
    step_input_guardduty["Finding"]["Types"] = [
        "Effects/Data Exposure/Policy:S3-BucketBlockPublicAccessDisabled"
    ]

    ssm_c = AWS.get_connection("ssm")
    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/BucketBlockPublicAccessDisabled",
                "Type": "String",
                "Value": '{"RunbookName":"ASR-TestConfigDoc","RunbookRole":"ASR-TestRole"}',
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/BucketBlockPublicAccessDisabled",
                "DataType": "text",
            }
        },
        {"Name": "/Solutions/SO0111/BucketBlockPublicAccessDisabled"},
    )

    ssmc_stub.activate()
    mocker.patch("boto3.client", return_value=ssm_c)

    response = lambda_handler(step_input_guardduty, {})

    assert response["workflow_data"] == expected_result["workflow_data"]
    assert response["workflowdoc"] == expected_result["workflowdoc"]
    assert response["workflowrole"] == expected_result["workflowrole"]

    ssmc_stub.deactivate()


def test_get_approval_inspector(mocker):
    """
    Verifies that it returns the fanout runbook name
    """
    os.environ["WORKFLOW_RUNBOOK"] = ""
    expected_result = {
        "workflowdoc": "ASR-TestConfigDoc",
        "workflowrole": "ASR-TestRole",
        "workflow_data": {
            "impact": "nondestructive",
            "approvalrequired": "false",
            "security_hub": "false",
        },
    }

    AWS = AWSCachedClient(get_region())
    step_input_inspector = step_input_config()
    step_input_inspector["Finding"]["ProductFields"] = {
        "aws/securityhub/ProductName": "Inspector",
        "attributes/RULE_TYPE": "InspectorRuleName",
    }

    ssm_c = AWS.get_connection("ssm")
    ssmc_stub = Stubber(ssm_c)

    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/InspectorRuleName",
                "Type": "String",
                "Value": '{"RunbookName":"ASR-TestConfigDoc","RunbookRole":"ASR-TestRole"}',
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/InspectorRuleName",
                "DataType": "text",
            }
        },
        {"Name": "/Solutions/SO0111/InspectorRuleName"},
    )

    ssmc_stub.activate()
    mocker.patch("boto3.client", return_value=ssm_c)
    response = lambda_handler(step_input_inspector, {})

    assert response["workflow_data"] == expected_result["workflow_data"]
    assert response["workflowdoc"] == expected_result["workflowdoc"]
    assert response["workflowrole"] == expected_result["workflowrole"]

    ssmc_stub.deactivate()
