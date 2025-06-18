# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict

import boto3
from botocore.config import Config


class EventType(TypedDict):
    accountid: str
    name: str


boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ssm():
    return boto3.client("ssm", config=boto_config)


def lambda_handler(event: EventType, _):
    """
    remediates SSM.4 by disabling public access to SSM documents
    On success returns True
    On failure returns NoneType
    """

    try:
        document_arn = event["document_arn"]
        document_name = document_arn.split("/")[1]
        document_perimissions = describe_document_permissions(document_name)
        if "all" in document_perimissions.get("AccountIds"):
            modify_document_permissions(document_name)
        else:
            exit(f"No change was made to {document_name}")

        verify_document_permissions = describe_document_permissions(document_name)

        if "all" not in verify_document_permissions.get("AccountIds"):
            return {"isPublic": "False"}
        else:
            raise RuntimeError

    except Exception as e:
        exit(f"Failed to retrieve the SSM Document permission: {str(e)}")


def describe_document_permissions(document_name):
    ssm_client = connect_to_ssm()
    try:
        document_permissions = ssm_client.describe_document_permission(
            Name=document_name, PermissionType="Share"
        )
        return document_permissions
    except Exception as e:
        exit(f"Failed to describe SSM Document {document_name}: {str(e)}")


def modify_document_permissions(document_name):
    ssm_client = connect_to_ssm()
    try:
        ssm_client.modify_document_permission(
            Name=document_name, AccountIdsToRemove=["all"], PermissionType="Share"
        )
    except Exception as e:
        exit(f"Failed to modify SSM Document {document_name}: {str(e)}")
