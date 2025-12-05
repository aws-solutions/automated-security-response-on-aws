# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Remediates SSM.4 and SSM.7 by disabling public access to SSM documents
"""
from typing import TypedDict

import boto3
from botocore.config import Config


class EventType(TypedDict):
    accountid: str
    name: str


BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ssm():
    return boto3.client("ssm", config=BOTO_CONFIG)


def get_document_name(event):
    """
    Extract document name from event supporting multiple input formats

    Supports:
    - DocumentArn: arn:aws:ssm:region:account:document/name (SSM.4/SSM.7)
    - DocumentName: name (direct name)
    - document_arn: arn:aws:ssm:region:account:document/name (legacy)
    """
    for key in ["DocumentArn", "DocumentName", "document_arn"]:
        if key in event:
            value = event[key]
            # Extract name from ARN if it contains '/'
            return value.split("/")[-1] if "/" in value else value

    raise ValueError(
        "Event must contain 'DocumentArn', 'DocumentName', or 'document_arn'"
    )


def lambda_handler(event: EventType, _):
    """
    Removes public access from an SSM document

    Returns:
        Dict with 'response': {'isPublic': 'False'} on success
    """
    document_name = get_document_name(event)
    ssm = connect_to_ssm()

    # Check current permissions
    response = ssm.describe_document_permission(
        Name=document_name, PermissionType="Share"
    )

    # Only modify if publicly shared
    if "all" not in response.get("AccountIds", []):
        return {"response": {"isPublic": "False"}}

    # Remove public access
    ssm.modify_document_permission(
        Name=document_name, AccountIdsToRemove=["all"], PermissionType="Share"
    )

    return {"response": {"isPublic": "False"}}
