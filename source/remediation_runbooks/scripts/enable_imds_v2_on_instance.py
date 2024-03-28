# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ec2():
    return boto3.client("ec2", config=boto_config)


def lambda_handler(event, _):
    """
    Enable IMDSv2 on an EC2 Instance.

    `event` should have the following keys and values:
    `instance_arn`: the ARN of the instance that does not have IMDSv2 enabled.

    `context` is ignored
    """

    instance_arn = event["instance_arn"]

    instance_id = instance_arn.split("/")[1]

    enable_imdsv2(instance_id)

    instance_attributes = describe_instance(instance_id)

    imds_v2_attribute = instance_attributes["Reservations"][0]["Instances"][0][
        "MetadataOptions"
    ]

    if imds_v2_attribute["HttpTokens"] == "required":
        return imds_v2_attribute

    raise RuntimeError(
        f"ASR Remediation failed - {instance_id} did not have IMDSv2 enabled."
    )


def enable_imdsv2(instance_id):
    """
    Changes EC2 Instance metadata options to require IMDSv2
    """
    ec2 = connect_to_ec2()
    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id, HttpTokens="required", HttpEndpoint="enabled"
        )

    except Exception as e:
        exit("There was an error enabling IMDSv2: " + str(e))


def describe_instance(instance_id):
    """
    Grabs Instance Attributes to verify IMDSv2 values were set as expected.
    """
    ec2 = connect_to_ec2()
    try:
        instance_attributes = ec2.describe_instances(InstanceIds=[instance_id])
        return instance_attributes

    except Exception as e:
        exit("Failed to get attributes of instance: " + str(e))
