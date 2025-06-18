# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Optional, TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


def connect_to_service(service):
    return boto3.client(service, config=boto_config)


class Event(TypedDict):
    GroupId: str


class GetPermissionsResponse(TypedDict):
    IngressPermissions: Optional[list]
    EgressPermissions: Optional[list]


class HandlerResponse(TypedDict):
    Status: str
    Message: str


def handler(event: Event, _) -> HandlerResponse:
    try:
        ec2_client = connect_to_service("ec2")
        group_id = event.get("GroupId")

        ip_permissions = get_permissions(group_id)
        ingress_permissions = ip_permissions.get("IngressPermissions")
        egress_permissions = ip_permissions.get("EgressPermissions")

        if ingress_permissions:
            ec2_client.revoke_security_group_ingress(
                GroupId=group_id, IpPermissions=ingress_permissions
            )
        if egress_permissions:
            ec2_client.revoke_security_group_egress(
                GroupId=group_id, IpPermissions=egress_permissions
            )

        return {
            "Status": "Success",
            "Message": f"Removed VPC default security group rules from group {group_id}",
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error removing VPC default security group rules: {str(e)}"
        )


def get_permissions(group_id: str) -> GetPermissionsResponse:
    ec2_client = connect_to_service("ec2")
    try:
        default_group = ec2_client.describe_security_groups(GroupIds=[group_id]).get(
            "SecurityGroups"
        )[0]
        return {
            "IngressPermissions": default_group.get("IpPermissions"),
            "EgressPermissions": default_group.get("IpPermissionsEgress"),
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error fetching permissions for security group {group_id}: {str(e)}"
        )
