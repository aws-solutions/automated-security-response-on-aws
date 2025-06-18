# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import boto3
import botocore.session
import pytest
import RemoveVPCDefaultSecurityGroupRules as remediation
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup():
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    response = ec2_client.create_vpc(
        CidrBlock="10.0.0.0/16",
    )
    vpc_id = response["Vpc"]["VpcId"]
    response = ec2_client.describe_security_groups(
        GroupNames=[
            "default",
        ],
    )
    return vpc_id, response["SecurityGroups"][0]["GroupId"]


def setup_client_stubber(client, method, mocker):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_client_error(
        method,
        service_error_code="ServiceException",
        service_message="Error",
    )
    mocker.patch(
        "RemoveVPCDefaultSecurityGroupRules.connect_to_service", return_value=client
    )
    return stubber


def add_ip_permissions(group_id):
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    test_ip_permissions_set = {
        "FromPort": 22,
        "IpProtocol": "tcp",
        "IpRanges": [
            {
                "CidrIp": "203.0.113.0/24",
                "Description": "Test Access Permissions",
            },
        ],
        "ToPort": 22,
    }
    ec2_client.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[test_ip_permissions_set],
    )
    ec2_client.authorize_security_group_egress(
        GroupId=group_id,
        IpPermissions=[test_ip_permissions_set],
    )


def get_security_group_permissions(group_id):
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    response = ec2_client.describe_security_groups(
        GroupIds=[
            group_id,
        ],
    )
    return (
        response["SecurityGroups"][0]["IpPermissions"],
        response["SecurityGroups"][0]["IpPermissionsEgress"],
    )


@mock_aws
def test_handler_with_ip_permissions():
    vpc_id, default_group_id = setup()
    add_ip_permissions(default_group_id)

    response = remediation.handler({"GroupId": default_group_id}, None)

    assert response["Status"] == "Success"
    ingress_permissions, egress_permissions = get_security_group_permissions(
        default_group_id
    )
    assert ingress_permissions == egress_permissions == []


@mock_aws
def test_handler_without_ip_permissions():
    vpc_id, default_group_id = setup()

    response = remediation.handler({"GroupId": default_group_id}, None)

    assert response["Status"] == "Success"
    ingress_permissions, egress_permissions = get_security_group_permissions(
        default_group_id
    )
    assert ingress_permissions == egress_permissions == []


def test_handler_on_invalid_event():
    with pytest.raises(Exception) as e:
        remediation.handler(
            {
                "InvalidKey": "test_value",
            },
            None,
        )
    assert re.match(
        r"Encountered error removing VPC default security group rules:", str(e.value)
    )


def test_get_permissions_error(mocker):
    ec2_stubber = setup_client_stubber("ec2", "describe_security_groups", mocker)

    ec2_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.get_permissions("my-group-id")

    assert re.match(
        r"Encountered error fetching permissions for security group", str(e.value)
    )
    ec2_stubber.deactivate()
