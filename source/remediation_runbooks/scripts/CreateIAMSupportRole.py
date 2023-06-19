# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from botocore.config import Config
import boto3

BOTO_CONFIG = Config(retries={"mode": "standard"})

responses = {}
responses["CreateIAMRoleResponse"] = []


def connect_to_iam(boto_config):
    return boto3.client("iam", config=boto_config)


def get_account(boto_config):
    return boto3.client('sts', config=boto_config).get_caller_identity()['Account']


def get_partition(boto_config):
    return boto3.client('sts', config=boto_config).get_caller_identity()['Arn'].split(':')[1]


def create_iam_role(_, __):
    account = get_account(BOTO_CONFIG)
    partition = get_partition(BOTO_CONFIG)

    aws_support_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
            }
        ],
    }

    role_name = "aws_incident_support_role"
    iam = connect_to_iam(BOTO_CONFIG)
    if not does_role_exist(iam, role_name):
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(aws_support_policy),
            Description="Created by ASR security hub remediation 1.20 rule",
            Tags=[
                {"Key": "Name", "Value": "CIS 1.20 aws support access role"},
            ],
        )

    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn=f"arn:{partition}:iam::aws:policy/AWSSupportAccess",
    )

    responses["CreateIAMRoleResponse"].append(
        {"Account": account, "RoleName": role_name}
    )

    return {"output": "IAM role creation is successful.", "http_responses": responses}


def does_role_exist(iam, role_name):
    """Check if the role name exists.

    Parameters
    ----------
    iam: iam client, required
    role_name: string, required

    Returns
    ------
        bool: returns if the role exists
    """
    role_exists = False

    try:
        response = iam.get_role(RoleName=role_name)

        if "Role" in response:
            role_exists = True

    except iam.exceptions.NoSuchEntityException:
        role_exists = False

    return role_exists
