# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the custom resource provider for deployment actions"""

from unittest.mock import ANY, patch

from cfnresponse import SUCCESS
from deployment_metrics_custom_resource import lambda_handler

metrics_data = {"Event": "SolutionCreate", "CloudWatchDashboardEnabled": "yes"}


def get_event(resource_type, request_type, cw_metrics_enabled):
    return {
        "ResourceType": resource_type,
        "RequestType": request_type,
        "ResourceProperties": {
            "CloudWatchMetricsDashboardEnabled": cw_metrics_enabled,
        },
    }


@patch("cfnresponse.send")
@patch("layer.metrics.Metrics.send_metrics")
def test_send_metrics(mock_send_metrics, mock_cfnresponse):
    event = get_event("Custom::DeploymentMetrics", "Create", "yes")
    lambda_handler(event, {})
    mock_send_metrics.assert_called_once_with(metrics_data)
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, ANY)
