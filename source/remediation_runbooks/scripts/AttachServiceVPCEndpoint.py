# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import List, Optional, TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


def connect_to_ec2():
    return boto3.client("ec2", config=boto_config)


class Event(TypedDict):
    ServiceName: str
    Region: str
    VPCId: str


def handler(event: Event, _):
    """
    Remediates by creating and attaching
    an AWS service endpoint to the VPC.
    """
    try:
        service_name = event["ServiceName"]
        aws_region = event["Region"]
        vpc_id = event["VPCId"]

        subnets = get_subnets(vpc_id)
        service_endpoint_name = get_service_endpoint_name(aws_region, service_name)

        vpc_endpoint_id = attach_vpc_endpoint(vpc_id, subnets, service_endpoint_name)
        return {
            "Message": (
                f"Successfully attached service endpoint {service_endpoint_name} to VPC {vpc_id}."
            ),
            "Status": "success",
            "VpcEndpointId": vpc_endpoint_id,
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error while attaching service endpoint to VPC: {str(e)}"
        )


def get_subnets(vpc_id: str) -> Optional[List[str]]:
    ec2_client = connect_to_ec2()
    try:
        paginator = ec2_client.get_paginator("describe_subnets")
        page_iterator = paginator.paginate(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [vpc_id],
                }
            ]
        )
        subnets = [
            subnet["SubnetId"]
            for page in page_iterator
            for subnet in page["Subnets"]
            if "SubnetId" in subnet
        ]
        return subnets
    except Exception as e:
        raise RuntimeError(f"Failed to list subnets in VPC {vpc_id}: {str(e)}")


def get_service_endpoint_name(aws_region: str, service_name: str) -> str:
    prefix = "cn." if aws_region in ["cn-north-1", "cn-northwest-1"] else ""
    return f"{prefix}com.amazonaws.{aws_region}.{service_name}"


def attach_vpc_endpoint(
    vpc_id: str, subnets: List[str], service_endpoint_name: str
) -> str:
    ec2_client = connect_to_ec2()
    try:
        dns_enabled = is_dns_enabled(vpc_id)
        response = ec2_client.create_vpc_endpoint(
            VpcEndpointType="Interface",
            VpcId=vpc_id,
            ServiceName=service_endpoint_name,
            SubnetIds=subnets,
            PrivateDnsEnabled=dns_enabled,
        )
        return response["VpcEndpoint"]["VpcEndpointId"]
    except Exception as e:
        raise RuntimeError(
            f"Failed to attach service endpoint {service_endpoint_name} to VPC {vpc_id}: {str(e)}"
        )


def is_dns_enabled(vpc_id: str) -> bool:
    ec2_client = connect_to_ec2()
    try:
        dns_support_enabled = ec2_client.describe_vpc_attribute(
            Attribute="enableDnsSupport",
            VpcId=vpc_id,
        )["EnableDnsSupport"]["Value"]

        dns_hostnames_enabled = ec2_client.describe_vpc_attribute(
            Attribute="enableDnsHostnames",
            VpcId=vpc_id,
        )["EnableDnsHostnames"]["Value"]

        return dns_support_enabled and dns_hostnames_enabled
    except Exception as e:
        raise RuntimeError(f"Failed to get VPC attributes for {vpc_id}: {str(e)}")
