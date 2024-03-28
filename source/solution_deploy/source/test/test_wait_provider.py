# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the custom resource provider for arbitrary wait"""

from unittest.mock import ANY, patch

from cfnresponse import SUCCESS
from wait_provider import lambda_handler


def get_event(create, update, delete, request_type):
    return {
        "ResourceProperties": {
            "CreateIntervalSeconds": str(create),
            "UpdateIntervalSeconds": str(update),
            "DeleteIntervalSeconds": str(delete),
        },
        "RequestType": request_type,
    }


@patch("cfnresponse.send")
@patch("wait_provider.wait_seconds")
def test_wait_create(mock_wait, mock_cfnresponse):
    """Create request waits for the correct amount of time"""
    create = 1.0
    event = get_event(create, 2.0, 3.0, "Create")
    lambda_handler(event, {})
    mock_wait.assert_called_once_with(create)
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, ANY)


@patch("cfnresponse.send")
@patch("wait_provider.wait_seconds")
def test_wait_update(mock_wait, mock_cfnresponse):
    """Update request waits for the correct amount of time"""
    update = 2.0
    event = get_event(1.0, update, 3.0, "Update")
    lambda_handler(event, {})
    mock_wait.assert_called_once_with(update)
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, ANY)


@patch("cfnresponse.send")
@patch("wait_provider.wait_seconds")
def test_wait_delete(mock_wait, mock_cfnresponse):
    """Delete request waits for the correct amount of time"""
    delete = 3.0
    event = get_event(1.0, 2.0, delete, "Delete")
    lambda_handler(event, {})
    mock_wait.assert_called_once_with(delete)
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, ANY)
