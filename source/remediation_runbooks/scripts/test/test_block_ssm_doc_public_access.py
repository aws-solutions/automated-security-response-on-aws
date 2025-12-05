# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the block_ssm_doc_public_access remediation script"""

from unittest.mock import patch

import boto3
import pytest
from block_ssm_doc_public_access import lambda_handler
from botocore.config import Config
from botocore.stub import Stubber

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def test_ssm4_with_document_arn():
    ssm = boto3.client("ssm", config=BOTO_CONFIG)
    stub_ssm = Stubber(ssm)
    document_name = "test-document"
    document_arn = f"arn:aws:ssm:us-east-1:111111111111:document/{document_name}"

    stub_ssm.add_response(
        "describe_document_permission",
        {"AccountIds": ["all"], "AccountSharingInfoList": []},
        {"Name": document_name, "PermissionType": "Share"},
    )

    stub_ssm.add_response(
        "modify_document_permission",
        {},
        {
            "Name": document_name,
            "AccountIdsToRemove": ["all"],
            "PermissionType": "Share",
        },
    )

    stub_ssm.activate()

    with patch("block_ssm_doc_public_access.connect_to_ssm", return_value=ssm):
        event = {"DocumentArn": document_arn}
        response = lambda_handler(event, {})
        assert response == {"response": {"isPublic": "False"}}

    stub_ssm.deactivate()


def test_legacy_document_arn_format():
    ssm = boto3.client("ssm", config=BOTO_CONFIG)
    stub_ssm = Stubber(ssm)
    document_name = "legacy-document"
    document_arn = f"arn:aws:ssm:us-east-1:111111111111:document/{document_name}"

    stub_ssm.add_response(
        "describe_document_permission",
        {"AccountIds": ["all"], "AccountSharingInfoList": []},
        {"Name": document_name, "PermissionType": "Share"},
    )

    stub_ssm.add_response(
        "modify_document_permission",
        {},
        {
            "Name": document_name,
            "AccountIdsToRemove": ["all"],
            "PermissionType": "Share",
        },
    )

    stub_ssm.activate()

    with patch("block_ssm_doc_public_access.connect_to_ssm", return_value=ssm):
        event = {"document_arn": document_arn}
        response = lambda_handler(event, {})
        assert response == {"response": {"isPublic": "False"}}

    stub_ssm.deactivate()


def test_with_document_name_only():
    ssm = boto3.client("ssm", config=BOTO_CONFIG)
    stub_ssm = Stubber(ssm)
    document_name = "test-document"

    stub_ssm.add_response(
        "describe_document_permission",
        {"AccountIds": ["all"], "AccountSharingInfoList": []},
        {"Name": document_name, "PermissionType": "Share"},
    )

    stub_ssm.add_response(
        "modify_document_permission",
        {},
        {
            "Name": document_name,
            "AccountIdsToRemove": ["all"],
            "PermissionType": "Share",
        },
    )

    stub_ssm.activate()

    with patch("block_ssm_doc_public_access.connect_to_ssm", return_value=ssm):
        event = {"DocumentName": document_name}
        response = lambda_handler(event, {})
        assert response == {"response": {"isPublic": "False"}}

    stub_ssm.deactivate()


def test_document_already_private():
    """Test when document is already private (no action needed)"""
    ssm = boto3.client("ssm", config=BOTO_CONFIG)
    stub_ssm = Stubber(ssm)
    document_name = "private-document"

    stub_ssm.add_response(
        "describe_document_permission",
        {"AccountIds": [], "AccountSharingInfoList": []},
        {"Name": document_name, "PermissionType": "Share"},
    )

    stub_ssm.activate()

    with patch("block_ssm_doc_public_access.connect_to_ssm", return_value=ssm):
        event = {"DocumentName": document_name}
        response = lambda_handler(event, {})
        assert response == {"response": {"isPublic": "False"}}

    stub_ssm.deactivate()


def test_missing_parameters():
    with pytest.raises(ValueError, match="Event must contain"):
        lambda_handler({}, {})
