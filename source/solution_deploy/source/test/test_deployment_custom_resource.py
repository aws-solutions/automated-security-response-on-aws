# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import ANY, patch

import pytest
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
def test_send_metrics(mock_send_metrics, mock_cfnresponse, request_type):
    stack_parameters = {
        "Parameter1": "value1",
        "Parameter2": "value2",
    }
    event = get_event("Custom::DeploymentMetrics", request_type, stack_parameters)

    expected_metrics_data = {
        "Event": f"Solution{request_type}",
        "RequestType": request_type,
        **stack_parameters,
    }

    lambda_handler(event, {})

    mock_send_metrics.assert_called_once_with(expected_metrics_data)
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, ANY)
