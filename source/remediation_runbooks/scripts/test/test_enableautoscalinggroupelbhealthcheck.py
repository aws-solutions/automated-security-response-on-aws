# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
import botocore.session
import EnableAutoScalingGroupELBHealthCheck_validate as validate
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name


# =====================================================================================
# EnableAutoScalingGroupELBHealthCheck_remediation SUCCESS
# =====================================================================================
def test_validation_success(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "AsgName": "my_asg",
        "region": my_region,
    }
    good_response = {
        "AutoScalingGroups": [
            {
                "AutoScalingGroupName": "sharr-test-autoscaling-1",
                "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:785d81e1-cd66-435d-96de-d6ed5416defd:autoScalingGroupName/sharr-test-autoscaling-1",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-05ad2fca4f4ea7d2f",
                    "LaunchTemplateName": "sharrtest",
                    "Version": "$Default",
                },
                "MinSize": 0,
                "MaxSize": 1,
                "DesiredCapacity": 0,
                "DefaultCooldown": 300,
                "AvailabilityZones": ["us-east-1b"],
                "LoadBalancerNames": [],
                "TargetGroupARNs": [
                    "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/WebDemoTarget/fc9a82512b92af62"
                ],
                "HealthCheckType": "ELB",
                "HealthCheckGracePeriod": 300,
                "Instances": [],
                "CreatedTime": "2021-01-27T14:08:16.949000+00:00",
                "SuspendedProcesses": [],
                "VPCZoneIdentifier": "subnet-86a594ab",
                "EnabledMetrics": [],
                "Tags": [],
                "TerminationPolicies": ["Default"],
                "NewInstancesProtectedFromScaleIn": False,
                "ServiceLinkedRoleARN": "arn:aws:iam::111111111111:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
            }
        ]
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    asg_client = botocore.session.get_session().create_client(
        "autoscaling", config=BOTO_CONFIG
    )

    asg_stubber = Stubber(asg_client)

    asg_stubber.add_response("describe_auto_scaling_groups", good_response)

    asg_stubber.activate()
    mocker.patch(
        "EnableAutoScalingGroupELBHealthCheck_validate.connect_to_autoscaling",
        return_value=asg_client,
    )
    assert validate.verify(event, {}) == {
        "response": {
            "message": "Autoscaling Group health check type updated to ELB",
            "status": "Success",
        }
    }

    asg_stubber.deactivate()


def test_validation_failed(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "AsgName": "my_asg",
        "region": my_region,
    }
    bad_response = {
        "AutoScalingGroups": [
            {
                "AutoScalingGroupName": "sharr-test-autoscaling-1",
                "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111111111111:autoScalingGroup:785d81e1-cd66-435d-96de-d6ed5416defd:autoScalingGroupName/sharr-test-autoscaling-1",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-05ad2fca4f4ea7d2f",
                    "LaunchTemplateName": "sharrtest",
                    "Version": "$Default",
                },
                "MinSize": 0,
                "MaxSize": 1,
                "DesiredCapacity": 0,
                "DefaultCooldown": 300,
                "AvailabilityZones": ["us-east-1b"],
                "LoadBalancerNames": [],
                "TargetGroupARNs": [
                    "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/WebDemoTarget/fc9a82512b92af62"
                ],
                "HealthCheckType": "EC2",
                "HealthCheckGracePeriod": 300,
                "Instances": [],
                "CreatedTime": "2021-01-27T14:08:16.949000+00:00",
                "SuspendedProcesses": [],
                "VPCZoneIdentifier": "subnet-86a594ab",
                "EnabledMetrics": [],
                "Tags": [],
                "TerminationPolicies": ["Default"],
                "NewInstancesProtectedFromScaleIn": False,
                "ServiceLinkedRoleARN": "arn:aws:iam::111111111111:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
            }
        ]
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    asg_client = botocore.session.get_session().create_client(
        "autoscaling", config=BOTO_CONFIG
    )

    asg_stubber = Stubber(asg_client)

    asg_stubber.add_response("describe_auto_scaling_groups", bad_response)

    asg_stubber.activate()
    mocker.patch(
        "EnableAutoScalingGroupELBHealthCheck_validate.connect_to_autoscaling",
        return_value=asg_client,
    )
    assert validate.verify(event, {}) == {
        "response": {
            "message": "Autoscaling Group health check type is not ELB",
            "status": "Failed",
        }
    }

    asg_stubber.deactivate()
