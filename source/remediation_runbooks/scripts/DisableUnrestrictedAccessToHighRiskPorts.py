# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})

# List of high risk ports to check for unrestricted access
PORTS_TO_CHECK = {
    20,
    21,
    22,
    23,
    25,
    110,
    135,
    143,
    445,
    1433,
    1434,
    3000,
    3306,
    3389,
    4333,
    5000,
    5432,
    5500,
    5601,
    8080,
    8088,
    8888,
    9200,
    9300,
}
# IPV4 and IPV6 open access
OPENIPV4 = "0.0.0.0/0"
OPENIPV6 = "::/0"
PROTOCOLS = {"tcp", "udp", "-1"}


def connect_to_ec2():
    return boto3.client("ec2", config=boto_config)


class Event(TypedDict):
    SecurityGroupId: str


def lambda_handler(event: Event, _):
    rules_deleted = []
    try:
        security_group_id = event["SecurityGroupId"]

        security_group_rules = get_security_group_rules(security_group_id)

        rules_deleted = delete_rules_with_access_to_high_risk_ports(
            security_group_id, security_group_rules
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


def delete_rules_with_access_to_high_risk_ports(
    security_group_id: str, security_group_rules: list
):
    ec2 = connect_to_ec2()
    rules_deleted = []
    for rule in security_group_rules:
        if rule_has_access_to_high_risk_ports(rule) and is_open_cidr(rule):
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=security_group_id,
                    SecurityGroupRuleIds=[
                        rule["SecurityGroupRuleId"],
                    ],
                )
                rules_deleted.append(rule["SecurityGroupRuleId"])
            except Exception as e:
                print(f"Failed to delete rule {rule['SecurityGroupRuleId']}: {str(e)}")
    return rules_deleted


def rule_has_access_to_high_risk_ports(rule: dict) -> bool:
    return (
        rule["IpProtocol"] in PROTOCOLS
        and not rule["IsEgress"]
        and (
            any(
                port in range(rule["FromPort"], rule["ToPort"] + 1)
                for port in PORTS_TO_CHECK
            )
            or (rule["FromPort"] == rule["ToPort"] == -1)
        )
    )


def is_open_cidr(rule: dict) -> bool:
    return ("CidrIpv4" in rule and rule["CidrIpv4"] == OPENIPV4) or (
        "CidrIpv6" in rule and rule["CidrIpv6"] == OPENIPV6
    )
