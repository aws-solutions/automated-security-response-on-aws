#!/usr/bin/python
###############################################################################
#  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import os
import json
import uuid
from botocore.config import Config
import boto3

boto_config = Config(retries={"mode": "standard"})

responses = {}
responses["CreateIAMRoleResponse"] = []


def connect_to_iam(boto_config):
    return boto3.client("iam", config=boto_config)


def create_iam_role(event, context):
    account = event["Account"]

    aws_support_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            }
        ],
    }

    role_name = "aws_incident_support_role"
    iam = connect_to_iam(boto_config)
    if does_role_exist(iam, role_name):
        lowercase_str = uuid.uuid4().hex
        role_name = f"{role_name}_{lowercase_str[0:8]}"

    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(aws_support_policy),
        Description="Created by SHARR security hub remediation 1.20 rule",
        Tags=[
            {"Key": "Name", "Value": "CIS 1.20 aws support access role"},
        ],
    )

    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess",
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

    except iam.exceptions.NoSuchEntityException as e:
        role_exists = False

    return role_exists