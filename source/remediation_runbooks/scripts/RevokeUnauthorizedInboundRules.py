# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict

import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

# IPV4 and IPV6 open access
OPENIPV4 = "0.0.0.0/0"
OPENIPV6 = "::/0"

PROTOCOLS = {"tcp", "udp", "-1"}


def connect_to_ec2():
    return boto3.client("ec2", config=BOTO_CONFIG)


class Event(TypedDict):
    SecurityGroupId: str
    AuthorizedTcpPorts: list
    AuthorizedUdpPorts: list


def lambda_handler(event: Event, _):
    rules_deleted = []
    try:
        security_group_id = event["SecurityGroupId"]
        authorized_tcp_ports = set(map(int, event["AuthorizedTcpPorts"]))
        authorized_udp_ports = set(map(int, event["AuthorizedUdpPorts"]))

        security_group_rules = get_security_group_rules(security_group_id)

        rules_deleted = revoke_unauthorized_rules(
            security_group_id,
            security_group_rules,
            authorized_tcp_ports,
            authorized_udp_ports,
        )
    except Exception as e:
        raise RuntimeError("Failed to remove security group rules: " + str(e))

    if not rules_deleted:
        raise RuntimeError(
            f"Could not find rules to delete for Security Group {security_group_id}. Please check the inbound "
            f"rules manually."
        )

    return {
        "message": "Successfully removed security group rules on " + security_group_id,
        "status": "Success",
        "rules_deleted": rules_deleted,
    }


def get_security_group_rules(security_group_id: str) -> list:
    ec2 = connect_to_ec2()
    try:
        paginator = ec2.get_paginator("describe_security_group_rules")
        page_iterator = paginator.paginate(
            Filters=[
                {
                    "Name": "group-id",
                    "Values": [security_group_id],
                },
            ]
        )

        security_group_rules = []
        for page in page_iterator:
            security_group_rules.extend(page.get("SecurityGroupRules", []))

        return security_group_rules
    except Exception as e:
        exit("Failed to describe security group rules: " + str(e))


def check_unauthorized_ports(authorized_ports: set, rule: dict) -> bool:
    for port in range(rule["FromPort"], rule["ToPort"] + 1):
        if (port not in authorized_ports) and (
            ("CidrIpv4" in rule and rule["CidrIpv4"] == OPENIPV4)
            or ("CidrIpv6" in rule and rule["CidrIpv6"] == OPENIPV6)
        ):
            return True
    return False


def revoke_unauthorized_rules(
    security_group_id: str,
    security_group_rules: list,
    authorized_tcp_ports: set,
    authorized_udp_ports: set,
) -> list:
    ec2 = connect_to_ec2()
    rules_deleted = []
    for rule in security_group_rules:
        if rule["IpProtocol"] in PROTOCOLS and not rule["IsEgress"]:
            authorized_ports = (
                authorized_tcp_ports
                if rule["IpProtocol"] == "tcp"
                else authorized_udp_ports
            )
            if (rule["FromPort"] == rule["ToPort"] == -1) or check_unauthorized_ports(
                authorized_ports, rule
            ):
                try:
                    ec2.revoke_security_group_ingress(
                        GroupId=security_group_id,
                        SecurityGroupRuleIds=[
                            rule["SecurityGroupRuleId"],
                        ],
                    )
                    rules_deleted.append(rule["SecurityGroupRuleId"])
                except Exception as e:
                    print(
                        f"Failed to delete rule {rule['SecurityGroupRuleId']}: {str(e)}"
                    )
    return rules_deleted
