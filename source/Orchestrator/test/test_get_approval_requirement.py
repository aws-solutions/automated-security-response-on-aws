#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

"""
Unit Test: exec_ssm_doc.py
Run from /deployment/temp/source/Orchestrator after running build-s3-dist.sh
"""

import os
import pytest
import boto3
from botocore.stub import Stubber, ANY
from get_approval_requirement import lambda_handler
from awsapi_cached_client import AWSCachedClient
from pytest_mock import mocker

LOCAL_ACCOUNT = boto3.client('sts').get_caller_identity()['Account']
REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')

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
                "Original": "INFORMATIONAL"
            },
            "Title": "AutoScaling.1 Auto scaling groups associated with a load balancer should use load balancer health checks",
            "Description": "This control checks whether your Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For directions on how to fix this issue, please consult the AWS Security Hub Foundational Security Best Practices documentation.",
                    "Url": "https://docs.aws.amazon.com/console/securityhub/AutoScaling.1/remediation"
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
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1/finding/635ceb5d-3dfd-4458-804e-48a42cd723e4"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": "arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:785df3481e1-cd66-435d-96de-d6ed5416defd:autoScalingGroupName/sharr-test-autoscaling-1",
                    "Partition": "aws",
                    "Region": "us-east-1"
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "StatusReasons": [
                    {
                        "ReasonCode": "CONFIG_EVALUATIONS_EMPTY",
                        "Description": "AWS Config evaluated your resources against the rule. The rule did not apply to the AWS resources in its scope, the specified resources were deleted, or the evaluation results were deleted."
                    }
                ]
            },
            "WorkflowState": "NEW",
            "Workflow": {
                "Status": "NEW"
            },
            "RecordState": "ACTIVE"
        },
        "AutomationDocument": {
            "DocState": "ACTIVE",
            "SecurityStandardVersion": "1.0.0",
            "AccountId": "111111111111",
            "Message": "Document Status is not \"Active\": unknown",
            "AutomationDocId": "SHARR-AFSBP_1.0.0_AutoScaling.1",
            "RemediationRole": "SO0111-Remediate-AFSBP-1.0.0-AutoScaling.1",
            "ControlId": "AutoScaling.1",
            "SecurityStandard": "AFSBP",
            "SecurityStandardSupported": "True"
        },
    }

def test_get_approval_req(mocker):
    """
    Verifies that it returns the fanout runbook name
    """
    os.environ['WORKFLOW_RUNBOOK'] = 'SHARR-RunWorkflow'
    os.environ['WORKFLOW_RUNBOOK_ACCOUNT'] = 'member'
    expected_result = {
        'workflowdoc': "SHARR-RunWorkflow",
        'workflowaccount': '111111111111',
        'workflowrole': '',
        'workflow_data': {
            'impact': 'nondestructive',
            'approvalrequired': 'false'
        }
    }

    AWS = AWSCachedClient(REGION)
    account = AWS.get_connection('sts').get_caller_identity()['Account']
    step_input()['AutomationDocument']['AccountId'] = account

    ssm_c = AWS.get_connection('ssm')
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/shortname",
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/shortname",
                "DataType": "text"
            }
        },{
            "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/shortname"
        }
    )
    ssmc_stub.add_client_error(
        'get_parameter',
        'ParameterNotFound'
    )
    ssmc_stub.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:44.632000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "DataType": "text"
            }
        }
    )
    ssmc_stub.add_response(
        'describe_document',
        {
            "Document": {
                "Hash": "be480c5a8771035918c439a0c76e1471306a699b7f275fe7e0bea70903dc569a",
                "HashType": "Sha256",
                "Name": "SHARR-RunWorkflow",
                "Owner": "111111111111",
                "CreatedDate": "2021-05-13T09:01:20.399000-04:00",
                "Status": "Active",
                "DocumentVersion": "1",
                "Description": "### Document Name - SHARR-RunWorkflow",
                "Parameters": [
                    {
                        "Name": "AutomationAssumeRole",
                        "Type": "String",
                        "Description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
                        "DefaultValue": ""
                    },
                    {
                        "Name": "Finding",
                        "Type": "StringMap",
                        "Description": "The input from Step function for ASG1 finding"
                    }
                ],
                "PlatformTypes": [
                    "Windows",
                    "Linux",
                    "MacOS"
                ],
                "DocumentType": "Automation",
                "SchemaVersion": "0.3",
                "LatestVersion": "1",
                "DefaultVersion": "1",
                "DocumentFormat": "JSON",
                "Tags": []
            }
        },{
            "Name": "SHARR-RunWorkflow"
        }
    )

    ssmc_stub.activate()
    mocker.patch('get_approval_requirement._get_ssm_client', return_value=ssm_c)

    response = lambda_handler(step_input(), {})

    assert response['workflow_data'] == expected_result['workflow_data']
    assert response['workflowdoc'] == expected_result['workflowdoc']
    assert response['workflowaccount'] == expected_result['workflowaccount']
    assert response['workflowrole'] == expected_result['workflowrole']

    ssmc_stub.deactivate()

def test_get_approval_req_no_fanout(mocker):
    """
    Verifies that it does not return workflow_status at all
    """
    os.environ['WORKFLOW_RUNBOOK'] = ''
    expected_result = {
        'workflowdoc': "",
        'workflowaccount': '',
        'workflowrole': '',
        'workflow_data': {
            'impact': 'nondestructive',
            'approvalrequired': 'false'
        }
    }

    AWS = AWSCachedClient(REGION)
    account = AWS.get_connection('sts').get_caller_identity()['Account']
    step_input()['AutomationDocument']['AccountId'] = account

    ssm_c = AWS.get_connection('ssm')
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/shortname",
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/shortname",
                "DataType": "text"
            }
        },{
            "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/shortname"
        }
    )
    ssmc_stub.add_client_error(
        'get_parameter',
        'ParameterNotFound'
    )
    ssmc_stub.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:44.632000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "DataType": "text"
            }
        }
    )
    ssmc_stub.add_response(
        'describe_document',
        {
            "Document": {
                "Hash": "be480c5a8771035918c439a0c76e1471306a699b7f275fe7e0bea70903dc569a",
                "HashType": "Sha256",
                "Name": "SHARR-RunWorkflow",
                "Owner": "111111111111",
                "CreatedDate": "2021-05-13T09:01:20.399000-04:00",
                "Status": "Active",
                "DocumentVersion": "1",
                "Description": "### Document Name - SHARR-RunWorkflow",
                "Parameters": [
                    {
                        "Name": "AutomationAssumeRole",
                        "Type": "String",
                        "Description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
                        "DefaultValue": ""
                    },
                    {
                        "Name": "Finding",
                        "Type": "StringMap",
                        "Description": "The input from Step function for ASG1 finding"
                    }
                ],
                "PlatformTypes": [
                    "Windows",
                    "Linux",
                    "MacOS"
                ],
                "DocumentType": "Automation",
                "SchemaVersion": "0.3",
                "LatestVersion": "1",
                "DefaultVersion": "1",
                "DocumentFormat": "JSON",
                "Tags": []
            }
        },{
            "Name": "SHARR-RunWorkflow"
        }
    )

    ssmc_stub.activate()
    mocker.patch('get_approval_requirement._get_ssm_client', return_value=ssm_c)

    response = lambda_handler(step_input(), {})
    print(response)

    assert response['workflow_data'] == expected_result['workflow_data']
    assert response['workflowdoc'] == expected_result['workflowdoc']
    assert response['workflowaccount'] == expected_result['workflowaccount']
    assert response['workflowrole'] == expected_result['workflowrole']

    ssmc_stub.deactivate()

#==================================================================================
def test_workflow_in_admin(mocker):
    """
    Verifies that it returns the fanout runbook name
    """
    os.environ['WORKFLOW_RUNBOOK'] = 'SHARR-RunWorkflow'
    os.environ['WORKFLOW_RUNBOOK_ACCOUNT'] = 'admin'
    os.environ['WORKFLOW_RUNBOOK_ROLE'] = 'someotheriamrole'
    expected_result = {
        'workflowdoc': "SHARR-RunWorkflow",
        'workflowaccount': LOCAL_ACCOUNT,
        'workflowrole': 'someotheriamrole',
        'workflow_data': {
            'impact': 'nondestructive',
            'approvalrequired': 'false'
        }
    }

    AWS = AWSCachedClient(REGION)
    account = AWS.get_connection('sts').get_caller_identity()['Account']
    step_input()['AutomationDocument']['AccountId'] = account

    ssm_c = AWS.get_connection('ssm')
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/shortname",
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:43.794000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/shortname",
                "DataType": "text"
            }
        },{
            "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/shortname"
        }
    )
    ssmc_stub.add_client_error(
        'get_parameter',
        'ParameterNotFound'
    )
    ssmc_stub.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-05-11T08:21:44.632000-04:00",
                "ARN": "arn:aws:ssm:us-east-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "DataType": "text"
            }
        }
    )
    ssmc_stub.add_response(
        'describe_document',
        {
            "Document": {
                "Hash": "be480c5a8771035918c439a0c76e1471306a699b7f275fe7e0bea70903dc569a",
                "HashType": "Sha256",
                "Name": "SHARR-RunWorkflow",
                "Owner": "111111111111",
                "CreatedDate": "2021-05-13T09:01:20.399000-04:00",
                "Status": "Active",
                "DocumentVersion": "1",
                "Description": "### Document Name - SHARR-RunWorkflow",
                "Parameters": [
                    {
                        "Name": "AutomationAssumeRole",
                        "Type": "String",
                        "Description": "(Optional) The ARN of the role that allows Automation to perform the actions on your behalf.",
                        "DefaultValue": ""
                    },
                    {
                        "Name": "Finding",
                        "Type": "StringMap",
                        "Description": "The input from Step function for ASG1 finding"
                    }
                ],
                "PlatformTypes": [
                    "Windows",
                    "Linux",
                    "MacOS"
                ],
                "DocumentType": "Automation",
                "SchemaVersion": "0.3",
                "LatestVersion": "1",
                "DefaultVersion": "1",
                "DocumentFormat": "JSON",
                "Tags": []
            }
        },{
            "Name": "SHARR-RunWorkflow"
        }
    )

    ssmc_stub.activate()
    mocker.patch('get_approval_requirement._get_ssm_client', return_value=ssm_c)

    response = lambda_handler(step_input(), {})
    print(response)
    assert response['workflow_data'] == expected_result['workflow_data']
    assert response['workflowdoc'] == expected_result['workflowdoc']
    assert response['workflowaccount'] == expected_result['workflowaccount']
    assert response['workflowrole'] == expected_result['workflowrole']

    ssmc_stub.deactivate()
