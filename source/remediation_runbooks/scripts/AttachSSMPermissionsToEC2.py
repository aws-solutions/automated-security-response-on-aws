# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Optional

import boto3
from botocore.config import Config

SSM_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

boto_config = Config(retries={"mode": "standard"})


def connect_to_iam():
    return boto3.client("iam", config=boto_config)


def connect_to_ec2():
    return boto3.client("ec2", config=boto_config)


def lambda_handler(event, _):
    """
    Remediates SSM.1 by attaching the required
    permissions to the EC2 Instance to enable
    SSM management.
    """
    try:
        instance_arn = event["InstanceArn"]
        instance_id = instance_arn.split("/")[1]
        remediation_role = event["RemediationRole"]
        remediation_instance_profile_name = event["InstanceProfile"]

        existing_instance_profile = get_existing_instance_profile(instance_id)
        existing_iam_role_from_instance_profile = (
            get_iam_role_from_instance_profile(existing_instance_profile)
            if existing_instance_profile
            else None
        )

        if existing_iam_role_from_instance_profile:
            attach_ssm_managed_iam_policy(existing_iam_role_from_instance_profile)

        ssm_management_iam_role = (
            existing_iam_role_from_instance_profile or remediation_role
        )

        instance_profile = (
            existing_instance_profile or remediation_instance_profile_name
        )

        if existing_instance_profile and not existing_iam_role_from_instance_profile:
            setup_instance_profile(ssm_management_iam_role, instance_profile)

        if not existing_instance_profile:
            attach_instance_profile(instance_profile, instance_id)

        return {
            "message": f"Successfully added SSM permissions to instance {instance_id}.",
            "status": "Success",
        }
    except Exception as e:
        raise RuntimeError(f"Encountered error remediating SSM.1: {str(e)}")


def get_existing_instance_profile(instance_id: str) -> Optional[str]:
    ec2_client = connect_to_ec2()

    try:
        response = ec2_client.describe_iam_instance_profile_associations(
            Filters=[
                {"Name": "instance-id", "Values": [instance_id]},
                {"Name": "state", "Values": ["associated"]},
            ]
        )
        if response["IamInstanceProfileAssociations"]:
            return response["IamInstanceProfileAssociations"][0]["IamInstanceProfile"][
                "Arn"
            ].split("/")[1]
        else:
            return None
    except Exception as e:
        raise RuntimeError(
            f"Failed to describe profile attached to instance {instance_id}: {str(e)}"
        )


def get_iam_role_from_instance_profile(profile_name: str) -> Optional[str]:
    iam_client = connect_to_iam()

    try:
        response = iam_client.get_instance_profile(InstanceProfileName=profile_name)
        if response["InstanceProfile"]["Roles"]:
            # there can only be one role attached to an instance profile
            return response["InstanceProfile"]["Roles"][0]["RoleName"]
    except Exception as e:
        raise RuntimeError(
            f"Failed to get role from instance profile {profile_name}: {str(e)}"
        )

    return None


def attach_ssm_managed_iam_policy(role_name: str) -> None:
    iam_client = connect_to_iam()

    try:
        if not is_ssm_managed_policy_attached(role_name):
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=SSM_MANAGED_POLICY_ARN,
            )
    except Exception as e:
        raise RuntimeError(f"Failed to attach SSM managed policy to IAM role: {str(e)}")


def is_ssm_managed_policy_attached(role_name: str) -> bool:
    iam_client = connect_to_iam()

    try:
        paginator = iam_client.get_paginator("list_attached_role_policies")
        page_iterator = paginator.paginate(RoleName=role_name)

        attached_policies = []
        for page in page_iterator:
            attached_policies.extend(page["AttachedPolicies"])

        for policy in attached_policies:
            if policy["PolicyArn"] == SSM_MANAGED_POLICY_ARN:
                return True
    except Exception as e:
        print(f"Failed to list attached policies for IAM role {role_name}: {str(e)}")

    return False


def setup_instance_profile(role_name: str, instance_profile_name: str) -> None:
    iam_client = connect_to_iam()

    try:
        iam_client.add_role_to_instance_profile(
            InstanceProfileName=instance_profile_name,
            RoleName=role_name,
        )
    except Exception as e:
        raise RuntimeError(
            f"Failed to add role {role_name} to instance profile {instance_profile_name}: {str(e)}"
        )


def attach_instance_profile(profile_name: str, instance_id: str) -> None:
    ec2_client = connect_to_ec2()
    try:
        ec2_client.associate_iam_instance_profile(
            IamInstanceProfile={"Name": profile_name},
            InstanceId=instance_id,
        )
    except Exception as e:
        raise RuntimeError(
            f"Failed to associate instance profile {profile_name} with instance {instance_id}: {str(e)}\n It is "
            f"likely that there is already an instance profile associated with the Instance, "
            f"use the describe-iam-instance-profile-associations command to verify."
        )
