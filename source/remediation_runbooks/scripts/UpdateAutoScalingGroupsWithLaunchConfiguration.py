# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from mypy_boto3_apigateway import AutoScalingClient
else:
    AutoScalingClient = object

import boto3
from botocore.config import Config


def connect_to_auto_scaling(boto_config: Config) -> AutoScalingClient:
    return boto3.client("autoscaling", config=boto_config)


class Event(TypedDict):
    OldLaunchConfigurationName: str
    NewLaunchConfigurationName: str


def update_auto_scaling_groups_with_launch_configuration(event: Event, _):
    try:
        auto_scaling_groups = get_auto_scaling_groups()
        update_auto_scaling_groups(
            auto_scaling_groups,
            event["OldLaunchConfigurationName"],
            event["NewLaunchConfigurationName"],
        )

        return {
            "message": "Successfully updated auto scaling groups with launch configuration",
            "status": "Success",
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered an error updating auto scaling groups: {str(e)}"
        )


def get_auto_scaling_groups():
    autoscaling_client = connect_to_auto_scaling(Config(retries={"mode": "standard"}))
    paginator = autoscaling_client.get_paginator("describe_auto_scaling_groups")
    page_iterator = paginator.paginate()

    auto_scaling_groups = []
    for page in page_iterator:
        auto_scaling_groups += page["AutoScalingGroups"]

    return auto_scaling_groups


def update_auto_scaling_groups(
    auto_scaling_groups,
    old_launch_configuration_name: str,
    new_launch_configuation_name: str,
):
    autoscaling_client = connect_to_auto_scaling(Config(retries={"mode": "standard"}))

    for auto_scaling_group in auto_scaling_groups:
        if (
            auto_scaling_group["LaunchConfigurationName"]
            != old_launch_configuration_name
        ):
            continue

        autoscaling_client.update_auto_scaling_group(
            AutoScalingGroupName=auto_scaling_group["AutoScalingGroupName"],
            LaunchConfigurationName=new_launch_configuation_name,
        )
