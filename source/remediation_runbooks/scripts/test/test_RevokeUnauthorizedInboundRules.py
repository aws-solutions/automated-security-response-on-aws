# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `RevokeUnauthorizedInboundRules` remediation script"""

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws
from RevokeUnauthorizedInboundRules import lambda_handler as remediation

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

# IPV4 and IPV6 open access
OPENIPV4 = "0.0.0.0/0"
OPENIPV6 = "::/0"

# Example list of authorized TCP ports
AUTHORIZED_TCP_PORTS = ["80", "443"]

# Example list of authorized TCP ports
AUTHORIZED_UDP_PORTS = ["80", "443"]

# Set of authorized ports,
AUTHORIZED_PORTS_SET = {80, 443}

# Example ports for security group rules
# 123 should be removed by remediation
# 80 and 443 should remain
PORTS_FOR_SG_RULE = {123, 80, 443}

# Protocols to check
PROTOCOLS = {"tcp", "udp"}


def setup(mocker, client_response, group_id):
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    ec2_stubber = Stubber(ec2_client)
    mocker.patch(
        "RevokeUnauthorizedInboundRules.connect_to_ec2",
        return_value=ec2_client,
    )
    ec2_stubber.add_response(
        "describe_security_group_rules",
        client_response,
        {
            "Filters": [
                {
                    "Name": "group-id",
                    "Values": [
                        group_id,
                    ],
                },
            ],
        },
    )
    ec2_stubber.add_response(
        "revoke_security_group_ingress",
        {},
        {
            "GroupId": group_id,
            "SecurityGroupRuleIds": [
                client_response["SecurityGroupRules"][0]["SecurityGroupRuleId"],
            ],
        },
    )
    return ec2_stubber


def connect_to_ec2():
    return boto3.client("ec2", config=BOTO_CONFIG)


@mock_aws
def test_revoke_unauthorized_inbound_rules_ipv4():
    # Connect to EC2 and Config services
    ec2 = connect_to_ec2()

    # Create security group
    sg = ec2.create_security_group(
        GroupName="test_group", Description="Test security group"
    )

    # Get the security group ID
    sg_id = sg["GroupId"]

    # Add unrestricted TCP rules to security group
    for port in PORTS_FOR_SG_RULE:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "FromPort": port,
                    "IpProtocol": "tcp",
                    "IpRanges": [
                        {
                            "CidrIp": OPENIPV4,
                        },
                    ],
                    "ToPort": port,
                }
            ],
        )

    # Add unrestricted UDP rules to security group
    for port in PORTS_FOR_SG_RULE:
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "FromPort": port,
                    "IpProtocol": "udp",
                    "IpRanges": [
                        {
                            "CidrIp": OPENIPV4,
                        },
                    ],
                    "ToPort": port,
                }
            ],
        )

    # Execute remediation
    event = {
        "SecurityGroupId": sg_id,
        "AuthorizedTcpPorts": AUTHORIZED_TCP_PORTS,
        "AuthorizedUdpPorts": AUTHORIZED_UDP_PORTS,
    }
    remediation(event, {})

    # Gather updated security group rules
    security_group_rules = ec2.describe_security_group_rules(
        Filters=[
            {
                "Name": "group-id",
                "Values": [
                    sg_id,
                ],
            },
        ],
    )

    # Check that all open access rules are on authorized ports
    for rule in security_group_rules["SecurityGroupRules"]:
        # Check only TCP/UDP rules
        if rule["IpProtocol"] in PROTOCOLS and "CidrIpv4" in rule:
            # Check only IPv4 rules with open access
            if rule["CidrIpv4"] == OPENIPV4:
                # Check that ports are authorized
                for port in range(rule["FromPort"], rule["ToPort"] + 1):
                    assert port in AUTHORIZED_PORTS_SET


def test_revoke_unauthorized_inbound_rules_ipv6(mocker):
    group_id = "my-group-id"
    ec2_stubber = setup(
        mocker,
        {
            "SecurityGroupRules": [
                {
                    "SecurityGroupRuleId": "rule-id",
                    "IsEgress": False,
                    "FromPort": -1,
                    "IpProtocol": "-1",
                    "CidrIpv6": OPENIPV6,
                    "ToPort": -1,
                }
            ]
        },
        group_id,
    )
    ec2_stubber.activate()

    remediation(
        {
            "SecurityGroupId": group_id,
            "AuthorizedTcpPorts": AUTHORIZED_TCP_PORTS,
            "AuthorizedUdpPorts": AUTHORIZED_UDP_PORTS,
        },
        {},
    )

    ec2_stubber.assert_no_pending_responses()
    ec2_stubber.deactivate()


def test_revoke_unauthorized_inbound_rules_from_all(mocker):
    group_id = "my-group-id"
    ec2_stubber = setup(
        mocker,
        {
            "SecurityGroupRules": [
                {
                    "SecurityGroupRuleId": "rule-id",
                    "IsEgress": False,
                    "FromPort": -1,
                    "IpProtocol": "-1",
                    "CidrIpv4": OPENIPV4,
                    "ToPort": -1,
                }
            ]
        },
        group_id,
    )
    ec2_stubber.activate()

    remediation(
        {
            "SecurityGroupId": group_id,
            "AuthorizedTcpPorts": AUTHORIZED_TCP_PORTS,
            "AuthorizedUdpPorts": AUTHORIZED_UDP_PORTS,
        },
        {},
    )

    ec2_stubber.assert_no_pending_responses()
    ec2_stubber.deactivate()
