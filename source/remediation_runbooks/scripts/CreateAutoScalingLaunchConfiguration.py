# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, Dict, TypedDict

if TYPE_CHECKING:
    from mypy_boto3_apigateway import AutoScalingClient
else:
    AutoScalingClient = object

import boto3
from botocore.config import Config


def connect_to_auto_scaling(boto_config: Config) -> AutoScalingClient:
    return boto3.client("autoscaling", config=boto_config)


class Event(TypedDict):
    LaunchConfiguration: Dict


def create_auto_scaling_launch_configuration(event: Event, _):
    try:
        # If these are blank, the api call will fail
        if event["LaunchConfiguration"]["KernelId"] == "":
            del event["LaunchConfiguration"]["KernelId"]

        if event["LaunchConfiguration"]["RamdiskId"] == "":
            del event["LaunchConfiguration"]["RamdiskId"]

        autoscaling_client = connect_to_auto_scaling(
            Config(retries={"mode": "standard"})
        )
        autoscaling_client.create_launch_configuration(**event["LaunchConfiguration"])

        return {
            "message": "Successfully created auto scaling launch configuration",
            "status": "Success",
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered an error creating auto scaling launch configuration: {str(e)}"
        )
