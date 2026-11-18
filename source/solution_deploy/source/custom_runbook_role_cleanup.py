# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Deletes the Custom Runbook remediation roles ASR created in this account when the Member
Roles stack is deleted.

ASR creates these roles at runtime, outside CloudFormation, and caps each one with the
stack's remediation permissions boundary. IAM refuses to delete a managed policy that is
still a role's permissions boundary, so without this cleanup the stack delete ends in
DELETE_FAILED on the boundary policy."""

from __future__ import annotations

from collections.abc import Mapping
from logging import getLogger
from os import getenv
from typing import TYPE_CHECKING, TypedDict

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

import cfnresponse

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.data_classes import (
        CloudFormationCustomResourceEvent,
    )
    from aws_lambda_powertools.utilities.typing import LambdaContext
    from mypy_boto3_cloudformation.client import CloudFormationClient
    from mypy_boto3_iam.client import IAMClient

logger = getLogger(__name__)
# basicConfig is a no-op in Lambda, whose runtime has already configured the root logger.
# fmt: off
logger.setLevel(getenv("LOG_LEVEL", "INFO"))  # NOSONAR This configures logging based on the environment variable that is set.
# fmt: on

# A stable ID means an update never replaces the resource, so CloudFormation never sends a
# Delete for it while the stack lives on.
PHYSICAL_RESOURCE_ID = "CustomRunbookRoleCleanup"
CUSTOM_RUNBOOK_TAG_KEY = "aws-solutions:custom-runbook"

BOTO_CONFIG = Config(retries={"mode": "standard"}, connect_timeout=5, read_timeout=10)
IAM_CLIENT: IAMClient = boto3.client("iam", config=BOTO_CONFIG)
CLOUDFORMATION_CLIENT: CloudFormationClient = boto3.client(
    "cloudformation", config=BOTO_CONFIG
)


class RoleCleanupError(Exception):
    """The cleanup could not finish; the message is the reason CloudFormation shows."""


class CleanupRequest(TypedDict):
    role_name_prefix: str
    boundary_policy_arn: str


def lambda_handler(
    event: CloudFormationCustomResourceEvent, context: LambdaContext
) -> None:
    try:
        if event["RequestType"] == "Delete":
            delete_custom_runbook_roles_if_stack_deleted(event)
    # An unanswered custom resource hangs the stack for an hour, so every error is reported.
    except Exception as error:  # NOSONAR
        logger.exception("Custom Runbook role cleanup failed")
        cfnresponse.send(
            event,
            context,
            cfnresponse.FAILED,
            {},
            PHYSICAL_RESOURCE_ID,
            reason=f"Custom Runbook role cleanup failed: {error}",
        )
        return
    cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, PHYSICAL_RESOURCE_ID)


def delete_custom_runbook_roles_if_stack_deleted(
    event: CloudFormationCustomResourceEvent,
) -> None:
    # A rollback of a failed update also deletes a resource that update added. Deleting the roles
    # then would break every deployed Custom Runbook in an account that keeps running ASR.
    if not is_stack_being_deleted(event["StackId"]):
        logger.info("Stack is not being deleted; keeping Custom Runbook roles")
        return

    request = validate_event(event)
    role_names = find_custom_runbook_roles(
        role_name_prefix=request["role_name_prefix"],
        boundary_policy_arn=request["boundary_policy_arn"],
    )
    logger.info("Deleting %d Custom Runbook roles: %s", len(role_names), role_names)
    failures: list[str] = []
    for role_name in role_names:
        try:
            delete_role(role_name)
        except (ClientError, BotoCoreError) as error:
            logger.error("Could not delete role %s: %s", role_name, error)
            failures.append(f"{role_name} ({error})")
    if failures:
        raise RoleCleanupError(
            "Could not delete these Custom Runbook roles, which still use the "
            f"remediation permissions boundary: {', '.join(failures)}"
        )


def validate_event(event: CloudFormationCustomResourceEvent) -> CleanupRequest:
    properties = event["ResourceProperties"]
    return CleanupRequest(
        role_name_prefix=require_property(properties, "RoleNamePrefix"),
        boundary_policy_arn=require_property(properties, "PermissionsBoundaryArn"),
    )


def require_property(properties: Mapping[str, object], property_name: str) -> str:
    value = properties.get(property_name)
    if not isinstance(value, str) or not value:
        raise RoleCleanupError(f"{property_name} must be a non-empty string")
    return value


def is_stack_being_deleted(stack_id: str) -> bool:
    stacks = CLOUDFORMATION_CLIENT.describe_stacks(StackName=stack_id)["Stacks"]
    return bool(stacks) and stacks[0]["StackStatus"] == "DELETE_IN_PROGRESS"


def find_custom_runbook_roles(
    *, role_name_prefix: str, boundary_policy_arn: str
) -> list[str]:
    """Roles ASR created for Custom Runbooks: the name prefix, this stack's boundary, and the
    ASR custom-runbook tag must all match, so a role ASR did not create is never deleted.
    """
    role_names: list[str] = []
    for page in IAM_CLIENT.get_paginator("list_roles").paginate():
        for listed_role in page["Roles"]:
            if not listed_role["RoleName"].startswith(role_name_prefix):
                continue
            # ListRoles returns neither the permissions boundary nor the tags.
            role = IAM_CLIENT.get_role(RoleName=listed_role["RoleName"])["Role"]
            boundary_arn = role.get("PermissionsBoundary", {}).get(
                "PermissionsBoundaryArn"
            )
            tag_keys = {tag["Key"] for tag in role.get("Tags", [])}
            if (
                boundary_arn == boundary_policy_arn
                and CUSTOM_RUNBOOK_TAG_KEY in tag_keys
            ):
                role_names.append(role["RoleName"])
    return role_names


def delete_role(role_name: str) -> None:
    """IAM deletes a role only once it has no inline or attached policies."""
    for inline_page in IAM_CLIENT.get_paginator("list_role_policies").paginate(
        RoleName=role_name
    ):
        for policy_name in inline_page["PolicyNames"]:
            IAM_CLIENT.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    for attached_page in IAM_CLIENT.get_paginator(
        "list_attached_role_policies"
    ).paginate(RoleName=role_name):
        for attached_policy in attached_page["AttachedPolicies"]:
            IAM_CLIENT.detach_role_policy(
                RoleName=role_name, PolicyArn=attached_policy["PolicyArn"]
            )
    IAM_CLIENT.delete_role(RoleName=role_name)
    logger.info("Deleted Custom Runbook role %s", role_name)
