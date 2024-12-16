# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from UpdateLaunchConfigurationToRequireIMDSv2 import update_launch_configuration


def test_update_launch_configuration():
    launch_config = {
        "LaunchConfigurationARN": "arn:aws:...",
        "CreatedTime": "2023-01-01T00:00:00Z",
        "InstanceType": "t2.micro",
    }
    event = {
        "LaunchConfiguration": launch_config,
        "LaunchConfigurationName": "NewLaunchConfig",
    }

    response = update_launch_configuration(event, None)
    assert response == {
        "LaunchConfigurationName": "NewLaunchConfig",
        "InstanceType": "t2.micro",
        "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
    }
