# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `disable_publicip_auto_assign` remediation script"""

from unittest.mock import patch

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from disable_publicip_auto_assign import lambda_handler


def test_disable_publicip_auto_assign(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
    ec2 = boto3.client("ec2", config=BOTO_CONFIG)
    stub_ec2 = Stubber(ec2)
    clients = {"ec2": ec2}

    subnet_arn = "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-017e22c0195eb5ded"

    subnet_id = "subnet-017e22c0195eb5ded"

    stub_ec2.add_response(
        "modify_subnet_attribute",
        {},
        {"MapPublicIpOnLaunch": {"Value": False}, "SubnetId": subnet_id},
    )

    stub_ec2.add_response(
        "describe_subnets", describedSubnet, {"SubnetIds": [subnet_id]}
    )

    stub_ec2.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {"subnet_arn": subnet_arn}
        response = lambda_handler(event, {})
        assert response == {"MapPublicIpOnLaunch": False}


describedSubnet = {
    "Subnets": [
        {
            "AvailabilityZone": "string",
            "AvailabilityZoneId": "string",
            "AvailableIpAddressCount": 123,
            "CidrBlock": "string",
            "DefaultForAz": False,
            "EnableLniAtDeviceIndex": 123,
            "MapPublicIpOnLaunch": False,
            "MapCustomerOwnedIpOnLaunch": False,
            "CustomerOwnedIpv4Pool": "string",
            "State": "available",
            "SubnetId": "string",
            "VpcId": "string",
            "OwnerId": "string",
            "AssignIpv6AddressOnCreation": False,
            "Ipv6CidrBlockAssociationSet": [
                {
                    "AssociationId": "string",
                    "Ipv6CidrBlock": "string",
                    "Ipv6CidrBlockState": {
                        "State": "associating",
                        "StatusMessage": "string",
                    },
                },
            ],
            "Tags": [
                {"Key": "string", "Value": "string"},
            ],
            "SubnetArn": "string",
            "OutpostArn": "string",
            "EnableDns64": False,
            "Ipv6Native": False,
            "PrivateDnsNameOptionsOnLaunch": {
                "HostnameType": "ip-name",
                "EnableResourceNameDnsARecord": False,
                "EnableResourceNameDnsAAAARecord": False,
            },
        },
    ],
    "NextToken": "string",
}
