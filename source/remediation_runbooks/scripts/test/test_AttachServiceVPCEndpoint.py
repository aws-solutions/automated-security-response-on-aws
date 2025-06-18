# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import AttachServiceVPCEndpoint as remediation
import boto3
import botocore.session
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup(num_subnets):
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)

    response = ec2_client.create_vpc(
        CidrBlock="10.0.0.0/16",
    )
    vpc_id = response["Vpc"]["VpcId"]

    return vpc_id, setup_vpc_subnets(vpc_id, num_subnets)


def setup_vpc_subnets(vpc_id, num_subnets):
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)

    subnets = []
    for i in range(num_subnets):
        subnets.append(
            ec2_client.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.0.{str(i+1)}.0/24",
            )[
                "Subnet"
            ]["SubnetId"]
        )
    return subnets


def disable_dns(vpc_id):
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)

    ec2_client.modify_vpc_attribute(
        EnableDnsHostnames={"Value": False},
        EnableDnsSupport={"Value": False},
        VpcId=vpc_id,
    )


def setup_client_stubber(client, method, mocker):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_client_error(
        method,
        service_error_code="ServiceException",
        service_message="Error",
    )
    mocker.patch("AttachServiceVPCEndpoint.connect_to_ec2", return_value=client)
    return stubber


def get_subnets_from_vpc_endpoint(vpc_endpoint_id):
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    response = ec2_client.describe_vpc_endpoints(VpcEndpointIds=[vpc_endpoint_id])
    result = []
    for vpc_endpoint in response["VpcEndpoints"]:
        if "SubnetIds" in vpc_endpoint:
            result.extend(vpc_endpoint["SubnetIds"])
    return result


@mock_aws
def test_attach_service_endpoint_to_vpc():
    created_vpc_id, created_subets = setup(3)

    response = remediation.handler(
        {
            "ServiceName": "ec2",
            "Region": REGION,
            "VPCId": created_vpc_id,
        },
        None,
    )

    assert response["Status"] == "success"
    endpoint_subnets = get_subnets_from_vpc_endpoint(response["VpcEndpointId"])
    assert all(
        endpoint_subnet in created_subets for endpoint_subnet in endpoint_subnets
    )
    assert len(endpoint_subnets) == len(created_subets)


@mock_aws
def test_attach_service_endpoint_to_vpc_with_no_subnets():
    created_vpc_id, created_subets = setup(0)

    response = remediation.handler(
        {
            "ServiceName": "ec2",
            "Region": REGION,
            "VPCId": created_vpc_id,
        },
        None,
    )

    assert response["Status"] == "success"
    endpoint_subnets = get_subnets_from_vpc_endpoint(response["VpcEndpointId"])
    assert len(endpoint_subnets) == len(created_subets)


@mock_aws
def test_attach_service_endpoint_to_vpc_with_dns_disabled():
    created_vpc_id, created_subets = setup(0)
    disable_dns(created_vpc_id)

    response = remediation.handler(
        {
            "ServiceName": "ec2",
            "Region": REGION,
            "VPCId": created_vpc_id,
        },
        None,
    )

    assert response["Status"] == "success"
    endpoint_subnets = get_subnets_from_vpc_endpoint(response["VpcEndpointId"])
    assert len(endpoint_subnets) == len(created_subets)


def test_invalid_event():
    with pytest.raises(Exception) as e:
        remediation.handler(
            {
                "SomeValue": "test_value",
            },
            None,
        )
    assert re.match(
        r"Encountered error while attaching service endpoint to VPC: ", str(e.value)
    )


def test_attach_vpc_endpoint_error(mocker):
    ec2_stubber = setup_client_stubber("ec2", "create_vpc_endpoint", mocker)

    ec2_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.attach_vpc_endpoint("my-vpc", [], "my-service-endpoint")

    assert re.match(r"Failed to attach service endpoint", str(e.value))
    ec2_stubber.deactivate()


def test_is_dns_enabled_error(mocker):
    ec2_stubber = setup_client_stubber("ec2", "describe_vpc_attribute", mocker)

    ec2_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.is_dns_enabled("my-vpc")

    assert re.match(r"Failed to get VPC attributes", str(e.value))
    ec2_stubber.deactivate()
