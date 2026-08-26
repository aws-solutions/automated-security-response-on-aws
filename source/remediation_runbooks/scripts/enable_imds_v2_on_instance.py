# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

import boto3
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_ec2.client import EC2Client
    from mypy_boto3_ec2.type_defs import ModifyInstanceMetadataOptionsResultTypeDef
else:
    EC2Client = object


class Event(TypedDict):
    instance_arn: str


boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ec2() -> EC2Client:
    return boto3.client("ec2", config=boto_config)


def lambda_handler(event: Event, _: object) -> dict[str, str]:
    """
    Enable IMDSv2 on an EC2 Instance.

    `event` should have the following keys and values:
    `instance_arn`: the ARN of the instance that does not have IMDSv2 enabled.

    `context` is ignored
    """

    instance_arn = event["instance_arn"]

    instance_id = instance_arn.split("/")[1]

    response = enable_imdsv2(instance_id)

    return {
        "InstanceId": response["InstanceId"],
        "HttpTokens": response["InstanceMetadataOptions"]["HttpTokens"],
        "HttpEndpoint": response["InstanceMetadataOptions"]["HttpEndpoint"],
    }


def enable_imdsv2(instance_id: str) -> ModifyInstanceMetadataOptionsResultTypeDef:
    """
    Changes EC2 Instance metadata options to require IMDSv2
    """
    ec2 = connect_to_ec2()
    try:
        return ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="required",
            HttpEndpoint="enabled",
        )

    except Exception as e:
        raise RuntimeError(f"There was an error enabling IMDSv2: {e}")
