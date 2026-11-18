# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""IAM runs in moto so role, boundary and tag behavior is real; CloudFormation's stack
status is stubbed, because the code under test only reads it."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, Literal
from unittest.mock import MagicMock, patch

import boto3
import pytest
from aws_lambda_powertools.utilities.data_classes import (
    CloudFormationCustomResourceEvent,
)
from moto import mock_aws

from cfnresponse import FAILED, SUCCESS

if TYPE_CHECKING:
    from mypy_boto3_iam.client import IAMClient
    from mypy_boto3_iam.type_defs import TagTypeDef

STACK_ID = "arn:aws:cloudformation:us-east-1:123456789012:stack/ASR-Member-Roles/guid"
ROLE_NAME_PREFIX = "SO0111-Remediate-Custom-"
TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ssm.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
BOUNDARY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "NotAction": "sts:*", "Resource": "*"}],
    }
)
RUNBOOK_TAG: TagTypeDef = {"Key": "aws-solutions:custom-runbook", "Value": "S3.17"}

RequestType = Literal["Create", "Update", "Delete"]


@pytest.fixture
def iam() -> Iterator[IAMClient]:
    with mock_aws():
        import custom_runbook_role_cleanup

        client: IAMClient = boto3.client("iam")
        with patch.object(custom_runbook_role_cleanup, "IAM_CLIENT", client):
            yield client


@pytest.fixture
def boundary_arn(iam: IAMClient) -> str:
    return iam.create_policy(
        PolicyName="SO0111-ASR-Remediation-Boundary", PolicyDocument=BOUNDARY_DOCUMENT
    )["Policy"]["Arn"]


@pytest.fixture
def cfnresponse_send() -> Iterator[MagicMock]:
    with patch("cfnresponse.send") as send:
        yield send


def stub_stack_status(status: str) -> AbstractContextManager[MagicMock]:
    import custom_runbook_role_cleanup

    client = MagicMock()
    client.describe_stacks.return_value = {"Stacks": [{"StackStatus": status}]}
    return patch.object(custom_runbook_role_cleanup, "CLOUDFORMATION_CLIENT", client)


def build_event(request_type: RequestType, boundary_arn: str) -> dict[str, Any]:
    return {
        "RequestType": request_type,
        "StackId": STACK_ID,
        "ResponseURL": "https://example.com/response",
        "ResourceProperties": {
            "RoleNamePrefix": ROLE_NAME_PREFIX,
            "PermissionsBoundaryArn": boundary_arn,
        },
    }


def invoke(event: dict[str, Any]) -> None:
    from custom_runbook_role_cleanup import lambda_handler

    lambda_handler(CloudFormationCustomResourceEvent(event), MagicMock())


def create_runbook_role(
    iam: IAMClient,
    role_name: str,
    *,
    boundary_arn: str | None,
    tags: list[TagTypeDef] | None = None,
) -> None:
    kwargs: dict[str, Any] = {
        "RoleName": role_name,
        "AssumeRolePolicyDocument": TRUST_POLICY,
        "Tags": [RUNBOOK_TAG] if tags is None else tags,
    }
    if boundary_arn:
        kwargs["PermissionsBoundary"] = boundary_arn
    iam.create_role(**kwargs)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="ASR-Custom-Runbook-Base",
        PolicyDocument=BOUNDARY_DOCUMENT,
    )


def role_names(iam: IAMClient) -> set[str]:
    return {role["RoleName"] for role in iam.list_roles()["Roles"]}


def sent_status(cfnresponse_send: MagicMock) -> str:
    status: str = cfnresponse_send.call_args.args[2]
    return status


def test_stack_delete_removes_custom_runbook_roles_so_the_boundary_can_be_deleted(
    iam: IAMClient, boundary_arn: str, cfnresponse_send: MagicMock
) -> None:
    # GIVEN two Custom Runbook roles that use the boundary, one with an attached policy too
    create_runbook_role(
        iam, "SO0111-Remediate-Custom-SC-2.0.0-S3.17", boundary_arn=boundary_arn
    )
    create_runbook_role(
        iam, "SO0111-Remediate-Custom-SC-2.0.0-SQS.1", boundary_arn=boundary_arn
    )
    iam.attach_role_policy(
        RoleName="SO0111-Remediate-Custom-SC-2.0.0-SQS.1", PolicyArn=boundary_arn
    )

    # WHEN the stack is deleted
    with stub_stack_status("DELETE_IN_PROGRESS"):
        invoke(build_event("Delete", boundary_arn))

    # THEN both roles are gone and IAM now lets the boundary policy be deleted
    assert role_names(iam) == set()
    iam.delete_policy(PolicyArn=boundary_arn)
    assert sent_status(cfnresponse_send) == SUCCESS


def test_stack_delete_keeps_roles_asr_did_not_create(
    iam: IAMClient, boundary_arn: str, cfnresponse_send: MagicMock
) -> None:
    other_boundary_arn = iam.create_policy(
        PolicyName="SomeOtherBoundary", PolicyDocument=BOUNDARY_DOCUMENT
    )["Policy"]["Arn"]
    # Each role misses exactly one of the three markers of an ASR Custom Runbook role.
    create_runbook_role(iam, "MyTeam-Remediate-Role", boundary_arn=boundary_arn)
    create_runbook_role(
        iam, "SO0111-Remediate-Custom-Untagged", boundary_arn=boundary_arn, tags=[]
    )
    create_runbook_role(
        iam, "SO0111-Remediate-Custom-OtherBoundary", boundary_arn=other_boundary_arn
    )
    create_runbook_role(iam, "SO0111-Remediate-Custom-NoBoundary", boundary_arn=None)

    with stub_stack_status("DELETE_IN_PROGRESS"):
        invoke(build_event("Delete", boundary_arn))

    assert role_names(iam) == {
        "MyTeam-Remediate-Role",
        "SO0111-Remediate-Custom-Untagged",
        "SO0111-Remediate-Custom-OtherBoundary",
        "SO0111-Remediate-Custom-NoBoundary",
    }
    assert sent_status(cfnresponse_send) == SUCCESS


@pytest.mark.parametrize(
    "status", ["UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_IN_PROGRESS"]
)
def test_delete_outside_a_stack_delete_keeps_the_roles(
    iam: IAMClient, boundary_arn: str, cfnresponse_send: MagicMock, status: str
) -> None:
    # A failed upgrade's rollback deletes a newly added resource; deployed runbooks must keep working.
    create_runbook_role(
        iam, "SO0111-Remediate-Custom-SC-2.0.0-S3.17", boundary_arn=boundary_arn
    )

    with stub_stack_status(status):
        invoke(build_event("Delete", boundary_arn))

    assert role_names(iam) == {"SO0111-Remediate-Custom-SC-2.0.0-S3.17"}
    assert sent_status(cfnresponse_send) == SUCCESS


@pytest.mark.parametrize("request_type", ["Create", "Update"])
def test_create_and_update_change_nothing(
    iam: IAMClient,
    boundary_arn: str,
    cfnresponse_send: MagicMock,
    request_type: RequestType,
) -> None:
    create_runbook_role(
        iam, "SO0111-Remediate-Custom-SC-2.0.0-S3.17", boundary_arn=boundary_arn
    )

    invoke(build_event(request_type, boundary_arn))

    assert role_names(iam) == {"SO0111-Remediate-Custom-SC-2.0.0-S3.17"}
    assert sent_status(cfnresponse_send) == SUCCESS
    assert cfnresponse_send.call_args.args[4] == "CustomRunbookRoleCleanup"


def test_a_role_that_cannot_be_deleted_fails_the_resource_and_names_the_role(
    iam: IAMClient, boundary_arn: str, cfnresponse_send: MagicMock
) -> None:
    create_runbook_role(
        iam, "SO0111-Remediate-Custom-SC-2.0.0-S3.17", boundary_arn=boundary_arn
    )
    # An instance profile is the one dependency ASR never creates; IAM then refuses the delete.
    iam.create_instance_profile(InstanceProfileName="profile")
    iam.add_role_to_instance_profile(
        InstanceProfileName="profile", RoleName="SO0111-Remediate-Custom-SC-2.0.0-S3.17"
    )

    with stub_stack_status("DELETE_IN_PROGRESS"):
        invoke(build_event("Delete", boundary_arn))

    assert sent_status(cfnresponse_send) == FAILED
    assert (
        "SO0111-Remediate-Custom-SC-2.0.0-S3.17"
        in cfnresponse_send.call_args.kwargs["reason"]
    )


def test_missing_properties_fail_the_delete(
    iam: IAMClient, cfnresponse_send: MagicMock
) -> None:
    event = build_event("Delete", "")
    with stub_stack_status("DELETE_IN_PROGRESS"):
        invoke(event)

    assert sent_status(cfnresponse_send) == FAILED
    assert "PermissionsBoundaryArn" in cfnresponse_send.call_args.kwargs["reason"]
