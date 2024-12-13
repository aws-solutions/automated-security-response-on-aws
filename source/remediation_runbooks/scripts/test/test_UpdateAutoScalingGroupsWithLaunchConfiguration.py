# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.config import Config
from moto import mock_aws
from UpdateAutoScalingGroupsWithLaunchConfiguration import (
    Event,
    update_auto_scaling_groups_with_launch_configuration,
)

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")

OLD_LAUNCH_CONFIGURATION_NAME = "LaunchConfiguration"
NEW_LAUNCH_CONFIGURATION_NAME = "NewLaunchConfiguration"

ADDITIONAL_LAUNCH_CONFIGURATION_PROPERTIES = {
    "UserData": "",
    "ClassicLinkVPCSecurityGroups": [],
    "BlockDeviceMappings": [
        {
            "Ebs": {
                "SnapshotId": "snap-05c65f9cd54535a5f",
                "VolumeType": "gp2",
                "Encrypted": False,
                "VolumeSize": 8,
                "DeleteOnTermination": True,
            },
            "DeviceName": "/dev/sda1",
        },
        {
            "Ebs": {
                "VolumeType": "gp2",
                "Encrypted": True,
                "VolumeSize": 20,
                "DeleteOnTermination": False,
            },
            "DeviceName": "/dev/sdh",
        },
        {
            "Ebs": {
                "VolumeType": "gp2",
                "Encrypted": True,
                "VolumeSize": 5,
                "DeleteOnTermination": False,
            },
            "DeviceName": "/dev/sdj",
        },
        {"NoDevice": True, "DeviceName": "/dev/sdc"},
        {
            "Ebs": {
                "VolumeType": "gp2",
                "Encrypted": True,
                "VolumeSize": 10,
                "DeleteOnTermination": False,
            },
            "DeviceName": "/dev/sdi",
        },
        {"NoDevice": True, "DeviceName": "/dev/sdb"},
    ],
    "IamInstanceProfile": "arn:aws:iam::123456789012:instance-profile/AmazonSSMRoleForInstancesQuickSetup",
    "EbsOptimized": False,
    "KeyName": "kp-remediation-instance",
    "ImageId": "ami-025d618a66d5e032d",
    "InstanceType": "t3.micro",
    "InstanceMonitoring": {"Enabled": False},
}

OLD_LAUNCH_CONFIGURATION = {
    "SecurityGroups": ["sg-00000000000000000"],
    "LaunchConfigurationName": OLD_LAUNCH_CONFIGURATION_NAME,
    "MetadataOptions": {
        "HttpTokens": "optional",
        "HttpEndpoint": "disabled",
        "HttpPutResponseHopLimit": 1,
    },
    **ADDITIONAL_LAUNCH_CONFIGURATION_PROPERTIES,
}


NEW_LAUNCH_CONFIGURATION = {
    "SecurityGroups": ["sg-00000000000000000"],
    "LaunchConfigurationName": NEW_LAUNCH_CONFIGURATION_NAME,
    "MetadataOptions": {
        "HttpTokens": "required",
        "HttpEndpoint": "enabled",
        "HttpPutResponseHopLimit": 1,
    },
    **ADDITIONAL_LAUNCH_CONFIGURATION_PROPERTIES,
}

ANOTHER_LAUNCH_CONFIGURATION_NAME = "AnotherLaunchConfiguration"
ANOTHER_LAUNCH_CONFIGURATION = {
    "SecurityGroups": ["sg-00000000000000000"],
    "LaunchConfigurationName": ANOTHER_LAUNCH_CONFIGURATION_NAME,
    "MetadataOptions": {
        "HttpTokens": "required",
        "HttpEndpoint": "enabled",
        "HttpPutResponseHopLimit": 1,
    },
    **ADDITIONAL_LAUNCH_CONFIGURATION_PROPERTIES,
}


def setup():
    # create the two launch configurations
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(**OLD_LAUNCH_CONFIGURATION)
    autoscaling_client.create_launch_configuration(**NEW_LAUNCH_CONFIGURATION)
    autoscaling_client.create_launch_configuration(**ANOTHER_LAUNCH_CONFIGURATION)

    # create some autoscaling groups that uses the old launch configuration
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="AutoScalingGroup",
        LaunchConfigurationName=OLD_LAUNCH_CONFIGURATION_NAME,
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a", "us-east-1b", "us-east-1c"],
    )

    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="AutoScalingGroup1",
        LaunchConfigurationName=OLD_LAUNCH_CONFIGURATION_NAME,
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a", "us-east-1b", "us-east-1c"],
    )

    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="AutoScalingGroup2",
        LaunchConfigurationName=OLD_LAUNCH_CONFIGURATION_NAME,
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a", "us-east-1b", "us-east-1c"],
    )

    # and some that don't
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="AutoScalingGroup3",
        LaunchConfigurationName=ANOTHER_LAUNCH_CONFIGURATION_NAME,
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a", "us-east-1b", "us-east-1c"],
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="AutoScalingGroup4",
        LaunchConfigurationName=ANOTHER_LAUNCH_CONFIGURATION_NAME,
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a", "us-east-1b", "us-east-1c"],
    )


@mock_aws
def test_update_auto_scaling_group_launch_configuration():
    setup()
    event = Event(
        {
            "OldLaunchConfigurationName": OLD_LAUNCH_CONFIGURATION_NAME,
            "NewLaunchConfigurationName": NEW_LAUNCH_CONFIGURATION_NAME,
        }
    )

    update_auto_scaling_groups_with_launch_configuration(event, None)

    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)

    autoscaling_groups = autoscaling_client.describe_auto_scaling_groups()[
        "AutoScalingGroups"
    ]

    assert (
        len(
            [
                group
                for group in autoscaling_groups
                if group["LaunchConfigurationName"] == NEW_LAUNCH_CONFIGURATION_NAME
            ]
        )
        == 3
    )

    assert (
        len(
            [
                group
                for group in autoscaling_groups
                if group["LaunchConfigurationName"] == OLD_LAUNCH_CONFIGURATION_NAME
            ]
        )
        == 0
    )
