# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import ANY, patch

import pytest
from botocore.exceptions import ClientError
from cfnresponse import SUCCESS
from deployment_metrics_custom_resource import lambda_handler


def get_event(resource_type, request_type, stack_parameters):
    return {
        "ResourceType": resource_type,
        "RequestType": request_type,
        "ResourceProperties": {
            "StackParameters": stack_parameters,
        },
    }


@pytest.mark.parametrize("request_type", ["Create", "Update", "Delete"])
@patch("cfnresponse.send")
@patch("layer.metrics.Metrics.send_metrics")
@patch(
    "deployment_metrics_custom_resource.boto3.client"
)  # The boto Stubber does not yet support describe_security_hub_v2, this can be replaced by the Stubber once this action is supported
def test_send_metrics(
    mock_boto3_client, mock_send_metrics, mock_cfnresponse, request_type
):
    # ARRANGE
    mock_securityhub = mock_boto3_client.return_value
    mock_securityhub.describe_security_hub_v2.return_value = {
        "HubV2Arn": "arn:aws:securityhub:us-east-1:123456789012:hub/default"
    }

    stack_parameters = {
        "Parameter1": "value1",
        "Parameter2": "value2",
    }
    event = get_event("Custom::DeploymentMetrics", request_type, stack_parameters)

    expected_metrics_data = {
        "Event": f"Solution{request_type}",
        "RequestType": request_type,
        "SecurityHubV2Enabled": True,
        **stack_parameters,
    }

    # ACT
    lambda_handler(event, {})

    # ASSERT
    mock_send_metrics.assert_called_once_with(expected_metrics_data)
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, ANY)


@pytest.mark.parametrize("request_type", ["Create", "Update", "Delete"])
@patch("cfnresponse.send")
@patch("layer.metrics.Metrics.send_metrics")
@patch("deployment_metrics_custom_resource.boto3.client")
def test_send_metrics_securityhub_v2_disabled(
    mock_boto3_client, mock_send_metrics, mock_cfnresponse, request_type
):
    # ARRANGE
    mock_securityhub = mock_boto3_client.return_value
    mock_securityhub.describe_security_hub_v2.return_value = {}

    stack_parameters = {
        "Parameter1": "value1",
        "Parameter2": "value2",
    }
    event = get_event("Custom::DeploymentMetrics", request_type, stack_parameters)

    expected_metrics_data = {
        "Event": f"Solution{request_type}",
        "RequestType": request_type,
        "SecurityHubV2Enabled": False,
        **stack_parameters,
    }

    # ACT
    lambda_handler(event, {})

    # ASSERT
    mock_send_metrics.assert_called_once_with(expected_metrics_data)
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, ANY)


@pytest.mark.parametrize("request_type", ["Create", "Update", "Delete"])
@patch("cfnresponse.send")
@patch("layer.metrics.Metrics.send_metrics")
@patch("deployment_metrics_custom_resource.boto3.client")
def test_send_metrics_securityhub_not_found(
    mock_boto3_client, mock_send_metrics, mock_cfnresponse, request_type
):
    # ARRANGE
    mock_securityhub = mock_boto3_client.return_value
    mock_securityhub.describe_security_hub_v2.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException"}}, "describe_security_hub_v2"
    )

    stack_parameters = {
        "Parameter1": "value1",
        "Parameter2": "value2",
    }
    event = get_event("Custom::DeploymentMetrics", request_type, stack_parameters)

    expected_metrics_data = {
        "Event": f"Solution{request_type}",
        "RequestType": request_type,
        "SecurityHubV2Enabled": False,
        **stack_parameters,
    }

    # ACT
    lambda_handler(event, {})

    # ASSERT
    mock_send_metrics.assert_called_once_with(expected_metrics_data)
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, ANY)
