# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
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
PROTOCOLS = {"tcp", "udp"}


def connect_to_ec2():
    return boto3.client("ec2", config=boto_config)


def lambda_handler(event, _):
    security_group_id = event["SecurityGroupId"]

    ec2 = connect_to_ec2()

    try:
        # Get the security group rules
        security_group_rules = ec2.describe_security_group_rules(
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

        for rule in security_group_rules["SecurityGroupRules"]:
            # Look for TCP or UDP ingress rules
            if rule["IpProtocol"] in PROTOCOLS and not rule["IsEgress"]:
                # Check for high risk ports
                if any(
                    port in range(rule["FromPort"], rule["ToPort"] + 1)
                    for port in PORTS_TO_CHECK
                ):
                    # Check for IPV4 open access
                    if "CidrIpv4" in rule and rule["CidrIpv4"] == OPENIPV4:
                        # Add rule to list
                        rules_deleted.append(rule["SecurityGroupRuleId"])
                        # Delete the rule
                        ec2.revoke_security_group_ingress(
                            GroupId=security_group_id,
                            SecurityGroupRuleIds=[
                                rule["SecurityGroupRuleId"],
                            ],
                        )

                    # Check for IPV6 open access
                    elif "CidrIpv6" in rule and rule["CidrIpv6"] == OPENIPV6:
                        # Add rule to list
                        rules_deleted.append(rule["SecurityGroupRuleId"])

                        # Delete the rule
                        ec2.revoke_security_group_ingress(
                            GroupId=security_group_id,
                            SecurityGroupRuleIds=[
                                rule["SecurityGroupRuleId"],
                            ],
                        )

        return {
            "message": "Successfully removed security group rules on "
            + security_group_id,
            "status": "Success",
            "rules_deleted": rules_deleted,
        }

    except Exception as e:
        exit("Failed to remove security group rules: " + str(e))
