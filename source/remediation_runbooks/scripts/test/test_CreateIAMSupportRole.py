# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
import botocore.session
import CreateIAMSupportRole as remediation
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
arbitrary_assume_role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {"AWS": "arn:aws:iam::123456789123:root"},
        }
    ],
}


def role_exists(role_name):
    iam = boto3.client("iam", config=BOTO_CONFIG)
    try:
        iam.get_role(RoleName=role_name)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False
    except Exception as e:
        raise e


def role_has_aws_support_policy(role_name):
    iam = boto3.client("iam", config=BOTO_CONFIG)
    response = iam.list_attached_role_policies(RoleName=role_name)
    for policy in response["AttachedPolicies"]:
        if policy["PolicyName"] == "AWSSupportAccess":
            return True
    return False


def create_iam_role(role_name):
    iam = boto3.client("iam", config=BOTO_CONFIG)
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(arbitrary_assume_role_policy),
    )


def setup_client_stubber(client, method, exception, mocker):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_client_error(
        method,
        service_error_code=exception,
        service_message="Error",
    )
    return stubber, client


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_create_iam_role():
    result = remediation.create_iam_role(None, None)

    assert result["output"] == "IAM role creation is successful."
    role_name = result["http_responses"]["CreateIAMRoleResponse"][0]["RoleName"]
    assert role_exists(role_name)
    assert role_has_aws_support_policy(role_name)


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_create_iam_role_with_existing_role():
    create_iam_role("aws_incident_support_role")

    result = remediation.create_iam_role(None, None)
    assert result["output"] == "IAM role creation is successful."
    role_name = result["http_responses"]["CreateIAMRoleResponse"][0]["RoleName"]
    assert role_has_aws_support_policy(role_name)
