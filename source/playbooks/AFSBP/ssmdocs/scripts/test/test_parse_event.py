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
import pytest

from afsbp_parse_input import parse_event

def event():
    return {
        'expected_control_id': 'AutoScaling.1',
        'parse_id_pattern': '^arn:(?:aws|aws-cn|aws-us-gov):autoscaling:(?:[a-z]{2}(?:-gov)?-[a-z]+-\\d):\\d{12}:autoScalingGroup:(?i:[0-9a-f]{11}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}):autoScalingGroupName/(.*)$',
        'Finding': {
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
        }
    }

def expected():
    return {
        "account_id": '111111111111',
        "resource_id": 'sharr-test-autoscaling-1',
        'control_id': 'AutoScaling.1',
        'testmode': False,
        "finding_id": 'arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1/finding/635ceb5d-3dfd-4458-804e-48a42cd723e4',
        "product_arn": 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
        "object": {
            "Type": 'AwsAccount',
            "Id": 'sharr-test-autoscaling-1',
            "OutputKey": 'Remediation.Output'
        },
        "matches": [ "sharr-test-autoscaling-1" ],
        'details': {},
        'resource': event().get('Finding').get('Resources')[0]
    }

def test_parse_event():
    parsed_event = parse_event(event(), {})
    assert parsed_event == expected()

def test_parse_event_multimatch():
    expected_result = expected()
    expected_result['matches'] = [
        "us-east-1",
        "sharr-test-autoscaling-1"
    ]
    test_event = event()
    test_event['resource_index'] = 2
    test_event['parse_id_pattern'] = '^arn:(?:aws|aws-cn|aws-us-gov):autoscaling:((?:[a-z]{2}(?:-gov)?-[a-z]+-\\d)):\\d{12}:autoScalingGroup:(?i:[0-9a-f]{11}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}):autoScalingGroupName/(.*)$'
    parsed_event = parse_event(test_event, {})
    assert parsed_event == expected_result

def test_bad_finding_id():
    test_event = event()
    test_event['Finding']['Id'] = "badvalue"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'ERROR: Finding Id is invalid: badvalue'

def test_bad_control_id():
    test_event = event()
    test_event['Finding']['Id'] = "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0//finding/635ceb5d-3dfd-4458-804e-48a42cd723e4"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'ERROR: Finding Id is invalid: arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0//finding/635ceb5d-3dfd-4458-804e-48a42cd723e4 - missing Control Id'

def test_control_id_nomatch():
    test_event = event()
    test_event['Finding']['Id'] = "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.1/finding/635ceb5d-3dfd-4458-804e-48a42cd723e4"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'ERROR: Control Id from input (EC2.1) does not match AutoScaling.1'

def test_bad_account_id():
    test_event = event()
    test_event['Finding']['AwsAccountId'] = "1234123412345"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'ERROR: AwsAccountId is invalid: 1234123412345'

def test_bad_productarn():
    test_event = event()
    test_event['Finding']['ProductArn'] = "badvalue"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'ERROR: ProductArn is invalid: badvalue'

def test_bad_resource_match():
    test_event = event()
    test_event['parse_id_pattern'] = '^arn:(?:aws|aws-cn|aws-us-gov):logs:::([A-Za-z0-9.-]{3,63})$'
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'ERROR: Invalid resource Id arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:785df3481e1-cd66-435d-96de-d6ed5416defd:autoScalingGroupName/sharr-test-autoscaling-1'

def test_no_resource_pattern():

    test_event = event()
    expected_result = expected()

    test_event['parse_id_pattern'] = ''
    expected_result['resource_id'] = 'arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:785df3481e1-cd66-435d-96de-d6ed5416defd:autoScalingGroupName/sharr-test-autoscaling-1'
    expected_result['matches'] = []
    expected_result['object']['Id'] = expected_result['resource_id']
    parsed_event = parse_event(test_event, {})
    assert parsed_event == expected_result

def test_no_resource_pattern_no_resource_id():
    test_event = event()

    test_event['parse_id_pattern'] = ''
    test_event['Finding']['Resources'][0]['Id'] = ''

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'ERROR: Resource Id is missing from the finding json Resources (Id)'

