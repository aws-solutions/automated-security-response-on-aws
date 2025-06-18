# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Dict, TypedDict


class Event(TypedDict):
    LaunchConfiguration: Dict
    LaunchConfigurationName: str


def event_handler(event: Event, _):
    launch_configuration = event["LaunchConfiguration"]
    launch_configuration["LaunchConfigurationName"] = event["LaunchConfigurationName"]
    launch_configuration["AssociatePublicIpAddress"] = False
    del launch_configuration["LaunchConfigurationARN"]
    del launch_configuration["CreatedTime"]
    return launch_configuration
