# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, Dict, TypedDict

if TYPE_CHECKING:
    from mypy_boto3_apigateway import AutoScalingClient
else:
    AutoScalingClient = object

import base64

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

        # DescribeLaunchConfigurations returns UserData base64-encoded, and boto3
        # base64-encodes UserData again in CreateLaunchConfiguration. Decode it here
        # so the new launch configuration keeps the original user data.
        if event["LaunchConfiguration"].get("UserData"):
            event["LaunchConfiguration"]["UserData"] = base64.b64decode(
                event["LaunchConfiguration"]["UserData"], validate=True
            )

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
