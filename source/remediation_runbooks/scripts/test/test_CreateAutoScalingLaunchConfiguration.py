# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re

import boto3
import pytest
from botocore.config import Config
from CreateAutoScalingLaunchConfiguration import (
    Event,
    create_auto_scaling_launch_configuration,
)
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")

LAUNCH_CONFIGURATION_NAME = "LaunchConfiguration"

LAUNCH_CONFIGURATION = {
    "SecurityGroups": ["sg-00000000000000000"],
    "LaunchConfigurationName": LAUNCH_CONFIGURATION_NAME,
    "MetadataOptions": {
        "HttpTokens": "required",
        "HttpEndpoint": "enabled",
        "HttpPutResponseHopLimit": 1,
    },
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
    "KernelId": "",
    "EbsOptimized": False,
    "KeyName": "kp-remediation-instance",
    "RamdiskId": "",
    "ImageId": "ami-025d618a66d5e032d",
    "InstanceType": "t3.micro",
    "InstanceMonitoring": {"Enabled": False},
}


@mock_aws
def test_create_auto_scaling_launch_configuration():
    event = Event({"LaunchConfiguration": LAUNCH_CONFIGURATION})

    create_auto_scaling_launch_configuration(event, None)

    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_configuration = autoscaling_client.describe_launch_configurations(
        LaunchConfigurationNames=[LAUNCH_CONFIGURATION_NAME]
    )["LaunchConfigurations"][0]

    assert launch_configuration["LaunchConfigurationName"] == LAUNCH_CONFIGURATION_NAME


@mock_aws
def test_invalid_event():
    launch_configuration = LAUNCH_CONFIGURATION.copy()
    del launch_configuration["LaunchConfigurationName"]
    event = Event({"LaunchConfiguration": launch_configuration})

    with pytest.raises(Exception) as e:
        create_auto_scaling_launch_configuration(event, None)
    assert re.match(
        r"Encountered an error creating auto scaling launch configuration:",
        str(e.value),
    )
