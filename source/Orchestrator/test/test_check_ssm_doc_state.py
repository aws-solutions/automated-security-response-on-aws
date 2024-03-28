# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit Test: check_ssm_doc_state.py
Run from /deployment/build/Orchestrator after running build-s3-dist.sh
"""
import os

import botocore.session
from botocore.config import Config
from botocore.stub import Stubber
from check_ssm_doc_state import lambda_handler
from layer.awsapi_cached_client import AWSCachedClient


def get_region():
    return os.getenv("AWS_DEFAULT_REGION")


BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())


def workflow_doc():
    return {
        "Document": {
            "Status": "Active",
            "Hash": "15b9f136e2cb0b47490dc5b38b439905e3f36fe1a8a411c1d278f2f2eb6fe633",
            "Name": "test-workflow",
            "Parameters": [
                {
                    "Type": "String",
                    "Name": "AutomationAssumeRole",
                    "Description": "The ARN of the role that allows Automation to perform the actions on your behalf.",
                },
                {
                    "Type": "StringMap",
                    "Name": "Finding",
                    "Description": "The Finding data from the Orchestrator Step Function",
                },
                {
                    "Type": "StringMap",
                    "Name": "SSMExec",
                    "Description": "Data for decision support in this runbook",
                },
                {
                    "Type": "String",
                    "Name": "RemediationDoc",
                    "Description": "the SHARR Remediation (ingestion) runbook to execute",
                },
            ],
            "Tags": [],
            "DocumentType": "Automation",
            "PlatformTypes": ["Windows", "Linux", "MacOS"],
            "DocumentVersion": "1",
            "HashType": "Sha256",
            "CreatedDate": 1633985125.065,
            "Owner": "111111111111",
            "SchemaVersion": "0.3",
            "DefaultVersion": "1",
            "DocumentFormat": "YAML",
            "LatestVersion": "1",
            "Description": "### Document Name - SHARR-Run_Remediation\n\n## What does this document do?\nThis document is executed by the AWS Security Hub Automated Response and Remediation Orchestrator Step Function. It implements controls such as manual approvals based on criteria passed by the Orchestrator.\n\n## Input Parameters\n* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.\n* Finding: (Required) json-formatted finding data\n* RemediationDoc: (Required) remediation runbook to execute after approval\n* SSMExec: (Required) json-formatted data for decision support in determining approval requirement\n",
        }
    }


def test_sunny_day(mocker):
    test_input = {
        "EventType": "Security Hub Findings - Custom Action",
        "Finding": {
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1/finding/635ceb5d-3dfd-4458-804e-48a42cd723e4",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1",
            "AwsAccountId": "111111111111",
            "ProductFields": {
                "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0",
                "ControlId": "AutoScaling.1",
                "StandardsControlArn": "arn:aws:securityhub:us-east-1:111111111111:control/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1",
                "aws/securityhub/ProductName": "Security Hub",
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": "arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:785df3481e1-cd66-435d-96de-d6ed5416defd:autoScalingGroupName/sharr-test-autoscaling-1",
                    "Partition": "aws",
                    "Region": "us-east-1",
                }
            ],
            "WorkflowState": "NEW",
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        },
    }

    expected_good_response = {
        "accountid": "111111111111",
        "automationdocid": "ASR-AFSBP_1.0.0_AutoScaling.1",
        "controlid": "AutoScaling.1",
        "logdata": [],
        "message": "",
        "remediation_status": "",
        "remediationrole": "SO0111-Remediate-AFSBP-1.0.0-AutoScaling.1",
        "resourceregion": "us-east-1",
        "securitystandard": "AFSBP",
        "securitystandardversion": "1.0.0",
        "standardsupported": "True",
        "status": "ACTIVE",
    }
    # use AWSCachedClient as it will us the same stub for any calls
    AWS = AWSCachedClient(get_region())
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
                "Name": "SHARRRemediation-AFSBP_1.0.0_AutoScaling.1",
                "Owner": "111111111111",
                "CreatedDate": "2021-05-13T09:01:20.399000-04:00",
                "Status": "Active",
                "DocumentVersion": "1",
                "Description": "### Document Name - SHARRRemediation-AFSBP_AutoScaling.1\n\n## What does this document do?\nThis document enables ELB healthcheck on a given AutoScaling Group using the [UpdateAutoScalingGroup] API.\n\n## Input Parameters\n* Finding: (Required) Security Hub finding details JSON\n* HealthCheckGracePeriod: (Optional) Health check grace period when ELB health check is Enabled\nDefault: 30 seconds\n* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.\n\n## Output Parameters\n* Remediation.Output - Output of DescribeAutoScalingGroups API.\n",
                "Parameters": [
                    {
                        "Name": "AutomationAssumeRole",
                        "Type": "String",
                        "Description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
                        "DefaultValue": "",
                    },
                    {
                        "Name": "SolutionId",
                        "Type": "String",
                        "Description": "AWS Solutions Solution Id",
                        "DefaultValue": "SO0111",
                    },
                    {
                        "Name": "Finding",
                        "Type": "StringMap",
                        "Description": "The input from Step function for ASG1 finding",
                    },
                    {
                        "Name": "HealthCheckGracePeriod",
                        "Type": "Integer",
                        "Description": "ELB Health Check Grace Period",
                        "DefaultValue": "30",
                    },
                    {
                        "Name": "SolutionVersion",
                        "Type": "String",
                        "Description": "AWS Solutions Solution Version",
                        "DefaultValue": "unknown",
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
        {"Name": "ASR-AFSBP_1.0.0_AutoScaling.1"},
    )

    ssmc_stub.activate()
    mocker.patch("check_ssm_doc_state._get_ssm_client", return_value=ssm_c)

    assert lambda_handler(test_input, {}) == expected_good_response
    ssmc_stub.deactivate()


def test_doc_not_active(mocker):
    test_input = {
        "EventType": "Security Hub Findings - Custom Action",
        "Finding": {
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1/finding/635ceb5d-3dfd-4458-804e-48a42cd723e4",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/AutoScaling.17",
            "AwsAccountId": "111111111111",
            "ProductFields": {
                "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0",
                "ControlId": "AutoScaling.1",
                "StandardsControlArn": "arn:aws:securityhub:us-east-1:111111111111:control/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.17",
                "aws/securityhub/ProductName": "Security Hub",
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
    }

    expected_good_response = {
        "accountid": "111111111111",
        "automationdocid": "ASR-AFSBP_1.0.0_AutoScaling.17",
        "controlid": "AutoScaling.17",
        "logdata": [],
        "message": "Document ASR-AFSBP_1.0.0_AutoScaling.17 does not exist.",
        "remediation_status": "",
        "resourceregion": "us-east-1",
        "remediationrole": "SO0111-Remediate-AFSBP-1.0.0-AutoScaling.17",
        "securitystandard": "AFSBP",
        "securitystandardversion": "1.0.0",
        "standardsupported": "True",
        "status": "NOTFOUND",
    }
    # use AWSCachedClient as it will us the same stub for any calls
    AWS = AWSCachedClient(get_region())
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
    ssmc_stub.add_client_error("describe_document", "InvalidDocument")

    ssmc_stub.activate()
    mocker.patch("check_ssm_doc_state._get_ssm_client", return_value=ssm_c)
    mocker.patch("check_ssm_doc_state.CloudWatchMetrics.send_metric", return_value=None)

    assert lambda_handler(test_input, {}) == expected_good_response
    ssmc_stub.deactivate()


def test_client_error(mocker):
    test_input = {
        "EventType": "Security Hub Findings - Custom Action",
        "Finding": {
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1/finding/635ceb5d-3dfd-4458-804e-48a42cd723e4",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1",
            "AwsAccountId": "111111111111",
            "ProductFields": {
                "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0",
                "ControlId": "AutoScaling.1",
                "StandardsControlArn": "arn:aws:securityhub:us-east-1:111111111111:control/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1",
                "aws/securityhub/ProductName": "Security Hub",
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": "arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:785df3481e1-cd66-435d-96de-d6ed5416defd:autoScalingGroupName/sharr-test-autoscaling-1",
                    "Partition": "aws",
                    "Region": "us-east-1",
                }
            ],
            "WorkflowState": "NEW",
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        },
    }

    expected_good_response = {
        "accountid": "111111111111",
        "automationdocid": "ASR-AFSBP_1.0.0_AutoScaling.1",
        "controlid": "AutoScaling.1",
        "logdata": [],
        "message": "An unhandled client error occurred: ADoorIsAjar",
        "remediation_status": "",
        "remediationrole": "SO0111-Remediate-AFSBP-1.0.0-AutoScaling.1",
        "resourceregion": "us-east-1",
        "securitystandard": "AFSBP",
        "securitystandardversion": "1.0.0",
        "standardsupported": "True",
        "status": "CLIENTERROR",
    }
    # use AWSCachedClient as it will us the same stub for any calls
    AWS = AWSCachedClient(get_region())
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
    ssmc_stub.add_client_error("describe_document", "ADoorIsAjar")

    ssmc_stub.activate()
    mocker.patch("check_ssm_doc_state._get_ssm_client", return_value=ssm_c)

    assert lambda_handler(test_input, {}) == expected_good_response

    ssmc_stub.deactivate()


def test_control_remap(mocker):
    test_input = {
        "EventType": "Security Hub Findings - Custom Action",
        "Finding": {
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.6",
            "RecordState": "ACTIVE",
            "Workflow": {"Status": "NEW"},
            "WorkflowState": "NEW",
            "ProductFields": {
                "RuleId": "1.6",
                "StandardsControlArn": "arn:aws:securityhub:us-east-1:111111111111:control/cis-aws-foundations-benchmark/v/1.2.0/1.6",
                "aws/securityhub/ProductName": "Security Hub",
            },
            "AwsAccountId": "111111111111",
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0/1.6/finding/3fe13eb6-b093-48b2-ba3b-b975347c3183",
            "Resources": [
                {
                    "Partition": "aws",
                    "Type": "AwsAccount",
                    "Region": "us-east-1",
                    "Id": "AWS::::Account:111111111111",
                }
            ],
        },
    }

    expected_good_response = {
        "accountid": "111111111111",
        "automationdocid": "ASR-CIS_1.2.0_1.5",
        "controlid": "1.6",
        "logdata": [],
        "message": "",
        "remediation_status": "",
        "resourceregion": "us-east-1",
        "remediationrole": "SO0111-Remediate-CIS-1.2.0-1.5",
        "securitystandard": "CIS",
        "securitystandardversion": "1.2.0",
        "standardsupported": "True",
        "status": "ACTIVE",
    }
    AWS = AWSCachedClient(get_region())
    ssm_c = AWS.get_connection("ssm")

    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname",
                "Type": "String",
                "Value": "CIS",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname",
                "DataType": "text",
            }
        },
        {"Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname"},
    )
    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/CIS/1.2.0/1.6/remap",
                "Type": "String",
                "Value": "1.5",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/CIS/1.2.0/1.6/remap",
                "DataType": "text",
            }
        },
        {"Name": "/Solutions/SO0111/CIS/1.2.0/1.6/remap"},
    )
    ssmc_stub.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/status",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:44.632000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/status",
                "DataType": "text",
            }
        },
        {"Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/status"},
    )

    ssmc_stub.add_response(
        "describe_document",
        {
            "Document": {
                "Hash": "9ca1ee49ff33196adad3fa19624d18943c018b78721999e256ecd4d2246cf1e5",
                "HashType": "Sha256",
                "Name": "SHARRRemediation-CIS_1.2.0_1.5",
                "Owner": "111111111111",
                "CreatedDate": "2021-05-13T09:01:08.342000-04:00",
                "Status": "Active",
                "DocumentVersion": "1",
                "Description": "### Document Name - SHARRRemediation-CIS_1.5\n\n## What does this document do?\nThis document establishes a default password policy.\n\n## Security Standards and Controls\n* CIS 1.5 - 1.11\n\n## Input Parameters\n* Finding: (Required) Security Hub finding details JSON\n* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.\n## Output Parameters\n* Remediation.Output\n\nSee AWSConfigRemediation-SetIAMPasswordPolicy\n",
                "Parameters": [
                    {
                        "Name": "AutomationAssumeRole",
                        "Type": "String",
                        "Description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
                        "DefaultValue": "",
                    },
                    {
                        "Name": "SolutionId",
                        "Type": "String",
                        "Description": "AWS Solutions Solution Id",
                        "DefaultValue": "SO0111",
                    },
                    {
                        "Name": "Finding",
                        "Type": "StringMap",
                        "Description": "The input from Step function for ASG1 finding",
                    },
                    {
                        "Name": "HealthCheckGracePeriod",
                        "Type": "Integer",
                        "Description": "ELB Health Check Grace Period",
                        "DefaultValue": "30",
                    },
                    {
                        "Name": "SolutionVersion",
                        "Type": "String",
                        "Description": "AWS Solutions Solution Version",
                        "DefaultValue": "unknown",
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
    )

    ssmc_stub.activate()
    mocker.patch("check_ssm_doc_state._get_ssm_client", return_value=ssm_c)

    assert lambda_handler(test_input, {}) == expected_good_response
    ssmc_stub.deactivate()


# ===============================================================================
def test_alt_workflow_with_role(mocker):
    test_input = {
        "EventType": "Security Hub Findings - Custom Action",
        "Finding": {
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.6",
            "RecordState": "ACTIVE",
            "Workflow": {"Status": "NEW"},
            "WorkflowState": "NEW",
            "ProductFields": {
                "RuleId": "1.6",
                "StandardsControlArn": "arn:aws:securityhub:us-east-1:111111111111:control/cis-aws-foundations-benchmark/v/1.2.0/1.6",
                "aws/securityhub/ProductName": "Security Hub",
            },
            "AwsAccountId": "111111111111",
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0/1.6/finding/3fe13eb6-b093-48b2-ba3b-b975347c3183",
            "Resources": [
                {
                    "Partition": "aws",
                    "Type": "AwsAccount",
                    "Region": "us-east-1",
                    "Id": "AWS::::Account:111111111111",
                }
            ],
        },
        "Workflow": {"WorkflowDocument": "AlternateDoc"},
    }

    expected_good_response = {
        "accountid": "111111111111",
        "automationdocid": "ASR-CIS_1.2.0_1.6",
        "controlid": "1.6",
        "logdata": [],
        "message": "",
        "remediation_status": "",
        "resourceregion": "us-east-1",
        "remediationrole": "SO0111-Remediate-CIS-1.2.0-1.6",
        "securitystandard": "CIS",
        "securitystandardversion": "1.2.0",
        "standardsupported": "True",
        "status": "ACTIVE",
    }

    ssm = botocore.session.get_session().create_client("ssm", config=BOTO_CONFIG)
    ssm_stubber = Stubber(ssm)
    ssm_stubber.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname",
                "Type": "String",
                "Value": "CIS",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.2.0/shortname",
                "DataType": "text",
            }
        },
        {"Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname"},
    )

    ssm_stubber.add_client_error("get_parameter", "ParameterNotFound")

    ssm_stubber.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:44.632000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "DataType": "text",
            }
        },
    )

    ssm_stubber.add_response("describe_document", workflow_doc())

    ssm_stubber.activate()
    mocker.patch("check_ssm_doc_state._get_ssm_client", return_value=ssm)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssm)

    result = lambda_handler(test_input, {})

    assert result == expected_good_response
