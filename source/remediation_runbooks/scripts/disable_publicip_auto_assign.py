# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ec2():
    return boto3.client("ec2", config=boto_config)


def lambda_handler(event, _):
    """
    Disable public IP auto assignment on a subnet.

    `event` should have the following keys and values:
    `subnet_arn`: the ARN of the subnet that has public IP auto assignment enabled.

    `context` is ignored
    """

    subnet_arn = event["subnet_arn"]

    subnet_id = subnet_arn.split("/")[1]

    disable_publicip_auto_assign(subnet_id)

    subnet_attributes = describe_subnet(subnet_id)

    public_ip_on_launch = subnet_attributes["Subnets"][0]["MapPublicIpOnLaunch"]

    if public_ip_on_launch is False:
        return {"MapPublicIpOnLaunch": public_ip_on_launch}

    raise RuntimeError(
        f"ASR Remediation failed - {subnet_id} did not have public IP auto assignment turned off."
    )


def disable_publicip_auto_assign(subnet_id):
    """
    Disables public IP Auto Assign on the subnet `subnet_id`
    """
    ec2 = connect_to_ec2()
    try:
        ec2.modify_subnet_attribute(
            MapPublicIpOnLaunch={"Value": False}, SubnetId=subnet_id
        )

    except Exception as e:
        exit("There was an error turning off public IP auto assignment: " + str(e))


def describe_subnet(subnet_id):
    """
    Grabs Subnet Attributes to verify subnet values were set as expected.
    """
    ec2 = connect_to_ec2()
    try:
        subnet_attributes = ec2.describe_subnets(SubnetIds=[subnet_id])
        return subnet_attributes

    except Exception as e:
        exit("Failed to get attributes of subnet: " + str(e))
