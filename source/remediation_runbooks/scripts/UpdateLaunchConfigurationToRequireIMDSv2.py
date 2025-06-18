# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict


class UpdateLaunchConfigurationEvent(TypedDict):
    LaunchConfiguration: dict
    LaunchConfigurationName: str


def update_launch_configuration(event: UpdateLaunchConfigurationEvent, _) -> dict:
    launch_configuration = event["LaunchConfiguration"]
    launch_configuration["LaunchConfigurationName"] = event["LaunchConfigurationName"]
    launch_configuration["MetadataOptions"] = {
        "HttpTokens": "required",
        "HttpEndpoint": "enabled",
    }
    del launch_configuration["LaunchConfigurationARN"]
    del launch_configuration["CreatedTime"]
    return launch_configuration
