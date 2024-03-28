# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

# IPV4 and IPV6 open access
OPENIPV4 = "0.0.0.0/0"
OPENIPV6 = "::/0"


def connect_to_ec2():
    return boto3.client("ec2", config=BOTO_CONFIG)


# Function to check if rule has open access to unauthorized ports
def check_unauthorized_ports(authorized_ports, rule):
    for port in range(rule["FromPort"], rule["ToPort"] + 1):
        if port not in authorized_ports:
            # Check for IPV4 open access
            if "CidrIpv4" in rule and rule["CidrIpv4"] == OPENIPV4:
                # Return True if rule has open access to unauthorized ports
                return True

            # Check for IPV6 open access
            elif "CidrIpv6" in rule and rule["CidrIpv6"] == OPENIPV6:
                # Return True if rule is removed
                return True

    # Return False if rule does not have open access to unauthorized ports
    return False


def lambda_handler(event, _):
    # Extract Security Group ID from event
    security_group_id = event["SecurityGroupId"]
    authorized_tcp_ports = set(map(int, event["AuthorizedTcpPorts"]))
    authorized_udp_ports = set(map(int, event["AuthorizedUdpPorts"]))

    # Connect to EC2 service
    ec2 = connect_to_ec2()

    # Get the security group rules
    paginator = ec2.get_paginator("describe_security_group_rules")

    security_group_rules = paginator.paginate(
        Filters=[
            {
                "Name": "group-id",
                "Values": [
                    security_group_id,
                ],
            },
        ],
    )

    # List to return rules that are deleted
    rules_deleted = []

    for page in security_group_rules:
        for rule in page["SecurityGroupRules"]:
            # Remove TCP ingress rules
            if (
                rule["IpProtocol"] == "tcp"
                and not rule["IsEgress"]
                and check_unauthorized_ports(authorized_tcp_ports, rule)
            ):
                # Delete the rule
                ec2.revoke_security_group_ingress(
                    GroupId=security_group_id,
                    SecurityGroupRuleIds=[
                        rule["SecurityGroupRuleId"],
                    ],
                )
                # Add rule to list of deleted rules
                rules_deleted.append(rule["SecurityGroupRuleId"])
            # Remove UDP ingress rules
            if (
                rule["IpProtocol"] == "udp"
                and not rule["IsEgress"]
                and check_unauthorized_ports(authorized_udp_ports, rule)
            ):
                # Delete the rule
                ec2.revoke_security_group_ingress(
                    GroupId=security_group_id,
                    SecurityGroupRuleIds=[
                        rule["SecurityGroupRuleId"],
                    ],
                )
                # Add rule to list of deleted rules
                rules_deleted.append(rule["SecurityGroupRuleId"])

    return {
        "message": "Successfully removed security group rules on " + security_group_id,
        "status": "Success",
        "rules_deleted": rules_deleted,
    }
