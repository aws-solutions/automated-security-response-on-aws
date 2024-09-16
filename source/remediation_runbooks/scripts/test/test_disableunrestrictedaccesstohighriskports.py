# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `DisableUnrestrictedAccessToHighRiskPorts` remediation script"""

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from DisableUnrestrictedAccessToHighRiskPorts import PORTS_TO_CHECK
from DisableUnrestrictedAccessToHighRiskPorts import lambda_handler as remediation
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

# IPV4 and IPV6 open access
OPENIPV4 = "0.0.0.0/0"
OPENIPV6 = "::/0"

PROTOCOLS = {"tcp", "udp"}


def setup(mocker, client_response, group_id):
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    ec2_stubber = Stubber(ec2_client)
    mocker.patch(
        "DisableUnrestrictedAccessToHighRiskPorts.connect_to_ec2",
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


@mock_aws
def test_disable_unrestricted_access_ipv4():
    ec2 = boto3.client("ec2", config=BOTO_CONFIG)

    # Create a new security group
    sg = ec2.create_security_group(GroupName="test", Description="test")

    # Get the security group ID
    sg_id = sg["GroupId"]
    event = {"SecurityGroupId": sg_id}

    # Add a TCP rule for each port that is allowed from anywhere
    for port in PORTS_TO_CHECK:
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

    # Add a UDP rule for each port that is allowed from anywhere
    for port in PORTS_TO_CHECK:
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

    remediation(event, {})

    # Get the security group rules
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

    for rule in security_group_rules["SecurityGroupRules"]:
        # Check only TCP/UDP rules
        if rule["IpProtocol"] in PROTOCOLS and "CidrIpv4" in rule:
            # Assert the rule does not have open IPV4 access to a high risk port
            assert not (
                any(
                    port in PORTS_TO_CHECK
                    for port in range(rule["FromPort"], rule["ToPort"] + 1)
                )
                and not rule["IsEgress"]
                and rule["CidrIpv4"] == OPENIPV4
            )


def test_disable_unrestricted_access_ipv6(mocker):
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
        },
        {},
    )

    ec2_stubber.assert_no_pending_responses()
    ec2_stubber.deactivate()


def test_disable_unrestricted_access_from_all(mocker):
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
        },
        {},
    )

    ec2_stubber.assert_no_pending_responses()
    ec2_stubber.deactivate()
