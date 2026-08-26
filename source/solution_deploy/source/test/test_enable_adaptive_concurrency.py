# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import patch

from cfnresponse import SUCCESS
from enable_adaptive_concurrency import lambda_handler


def get_event(request_type):
    return {
        "RequestType": request_type,
        "ResponseURL": "https://bogus",
        "StackId": "test-stack-id",
        "RequestId": "test-request-id",
        "LogicalResourceId": "test-resource-id",
    }


@patch("cfnresponse.send")
@patch("enable_adaptive_concurrency.SSM_CLIENT")
def test_create_enables_adaptive_concurrency(mock_ssm, mock_cfnresponse):
    event = get_event("Create")
    lambda_handler(event, {})

    mock_ssm.update_service_setting.assert_called_once_with(
        SettingId="/ssm/automation/enable-adaptive-concurrency",
        SettingValue="True",
    )
    mock_cfnresponse.assert_called_once_with(
        event, {}, SUCCESS, {"Message": "Adaptive concurrency enabled"}
    )


@patch("cfnresponse.send")
@patch("enable_adaptive_concurrency.SSM_CLIENT")
def test_update_does_nothing(mock_ssm, mock_cfnresponse):
    event = get_event("Update")
    lambda_handler(event, {})

    # Update should not call update_service_setting
    mock_ssm.update_service_setting.assert_not_called()
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, {})


@patch("cfnresponse.send")
@patch("enable_adaptive_concurrency.SSM_CLIENT")
def test_delete_does_nothing(mock_ssm, mock_cfnresponse):
    event = get_event("Delete")
    lambda_handler(event, {})

    # Delete should not call update_service_setting
    mock_ssm.update_service_setting.assert_not_called()
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, {})


@patch("cfnresponse.send")
@patch("enable_adaptive_concurrency.SSM_CLIENT")
def test_exception_sends_success_with_error_message(mock_ssm, mock_cfnresponse):
    mock_ssm.update_service_setting.side_effect = Exception("Test error")

    event = get_event("Create")
    lambda_handler(event, {})

    # Should send SUCCESS even on exception, with error details in response_data
    mock_cfnresponse.assert_called_once_with(
        event,
        {},
        SUCCESS,
        {
            "adaptive_concurrency_enabled": "false",
            "Message": "Adaptive concurrency not enabled: Test error",
        },
    )
