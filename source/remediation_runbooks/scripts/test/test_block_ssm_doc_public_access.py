# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `disable_public_sharing_of_ssm_doc` remediation script"""

from unittest.mock import patch

import boto3
from block_ssm_doc_public_access import lambda_handler
from botocore.config import Config
from botocore.stub import Stubber


def test_disable_public_sharing_of_ssm_document(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
    ssm = boto3.client("ssm", config=BOTO_CONFIG)
    stub_ssm = Stubber(ssm)
    clients = {"ssm": ssm}

    document_arn = "arn:aws:ssm:us-east-1:111111111111:document/test"
    document_name = "test"

    stub_ssm.add_response(
        "describe_document_permission",
        describedDocument,
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

    stub_ssm.add_response(
        "describe_document_permission",
        verifyDescribedDocument,
        {"Name": document_name, "PermissionType": "Share"},
    )

    stub_ssm.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {"document_arn": document_arn}
        response = lambda_handler(event, {})
        assert response == {"isPublic": "False"}


describedDocument = {
    "AccountIds": [
        "all",
    ],
    "AccountSharingInfoList": [
        {"AccountId": "all", "SharedDocumentVersion": "string"},
    ],
    "NextToken": "string",
}


verifyDescribedDocument = {
    "AccountIds": [],
    "AccountSharingInfoList": [],
    "NextToken": "string",
}
