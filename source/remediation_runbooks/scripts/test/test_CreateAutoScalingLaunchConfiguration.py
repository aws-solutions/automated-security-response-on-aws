# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import gzip
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


@mock_aws
def test_user_data_from_describe_is_not_double_encoded():
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    user_data = "#!/bin/bash\necho hello\n"
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="original",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
        UserData=user_data,
    )
    original = autoscaling_client.describe_launch_configurations(
        LaunchConfigurationNames=["original"]
    )["LaunchConfigurations"][0]
    # DescribeLaunchConfigurations returns the user data base64-encoded
    assert base64.b64decode(original["UserData"]).decode() == user_data

    event = Event(
        {
            "LaunchConfiguration": {
                "LaunchConfigurationName": "copy",
                "ImageId": original["ImageId"],
                "InstanceType": original["InstanceType"],
                "KernelId": "",
                "RamdiskId": "",
                "UserData": original["UserData"],
            }
        }
    )
    create_auto_scaling_launch_configuration(event, None)

    copy = autoscaling_client.describe_launch_configurations(
        LaunchConfigurationNames=["copy"]
    )["LaunchConfigurations"][0]
    assert copy["UserData"] == original["UserData"]
    assert base64.b64decode(copy["UserData"]).decode() == user_data


@mock_aws
def test_binary_user_data_is_preserved():
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    user_data = gzip.compress(b"#!/bin/bash\necho hello\n")
    encoded_user_data = base64.b64encode(user_data).decode()

    event = Event(
        {
            "LaunchConfiguration": {
                "LaunchConfigurationName": "copy",
                "ImageId": "ami-025d618a66d5e032d",
                "InstanceType": "t3.micro",
                "KernelId": "",
                "RamdiskId": "",
                "UserData": encoded_user_data,
            }
        }
    )
    create_auto_scaling_launch_configuration(event, None)

    copy = autoscaling_client.describe_launch_configurations(
        LaunchConfigurationNames=["copy"]
    )["LaunchConfigurations"][0]
    assert copy["UserData"] == encoded_user_data
    assert base64.b64decode(copy["UserData"]) == user_data
