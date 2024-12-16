# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from ConfigureAutoScalingLaunchConfigurationToDisablePublicIP import (
    Event,
    event_handler,
)

LAUNCH_CONFIGURATION_NAME = "LaunchConfiguration"
NEW_LAUNCH_CONFIGURATION_NAME = "LaunchConfiguration2"

LAUNCH_CONFIGURATION = {
    "SecurityGroups": ["sg-00000000000000000"],
    "LaunchConfigurationName": LAUNCH_CONFIGURATION_NAME,
    "LaunchConfigurationARN": "arn",
    "CreatedTime": "time",
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
    "AssociatePublicIpAddress": True,
}


def test_update_launch_configuration():
    event = Event(
        {
            "LaunchConfiguration": LAUNCH_CONFIGURATION,
            "LaunchConfigurationName": NEW_LAUNCH_CONFIGURATION_NAME,
        }
    )

    new_configuration = event_handler(event, None)

    assert new_configuration["AssociatePublicIpAddress"] is False
    assert new_configuration["LaunchConfigurationName"] == NEW_LAUNCH_CONFIGURATION_NAME
    assert "LaunchConfigurationARN" not in new_configuration
    assert "CreatedTime" not in new_configuration
