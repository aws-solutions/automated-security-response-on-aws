# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import urllib.parse
from unittest.mock import ANY, MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from cfnresponse import SUCCESS
from deployment_metrics_custom_resource import lambda_handler
from layer.awsapi_cached_client import AWSCachedClient
from moto import mock_aws


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
    "deployment_metrics_custom_resource.SECURITY_HUB_CLIENT"
)  # The boto Stubber does not yet support describe_security_hub_v2, this can be replaced by the Stubber once this action is supported
def test_send_metrics(
    mock_securityhub, mock_send_metrics, mock_cfnresponse, request_type
):
    # ARRANGE
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
@patch("deployment_metrics_custom_resource.SECURITY_HUB_CLIENT")
def test_send_metrics_securityhub_v2_disabled(
    mock_securityhub, mock_send_metrics, mock_cfnresponse, request_type
):
    # ARRANGE
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


@pytest.mark.parametrize(
    "version_parameter_property, expected_version",
    [
        ({"VersionParameterName": "/Solutions/SO0111/member-version"}, "v2.0.0"),
        ({}, "v1.0.0"),
    ],
)
@mock_aws
# Earlier tests leave SSM clients created outside mock_aws in this class-level cache.
@patch.object(AWSCachedClient, "client", {})
@patch("cfnresponse.send")
@patch("layer.metrics.urlopen")
@patch("deployment_metrics_custom_resource.SECURITY_HUB_CLIENT")
def test_send_metrics_reports_version_from_the_named_parameter(
    mock_securityhub: MagicMock,
    mock_urlopen: MagicMock,
    mock_cfnresponse: MagicMock,
    version_parameter_property: dict[str, str],
    expected_version: str,
) -> None:
    # ARRANGE
    mock_securityhub.describe_security_hub_v2.return_value = {}
    ssm = boto3.client("ssm", region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    ssm.put_parameter(Name="/Solutions/SO0111/version", Value="v1.0.0", Type="String")
    ssm.put_parameter(
        Name="/Solutions/SO0111/member-version", Value="v2.0.0", Type="String"
    )
    event = get_event("Custom::DeploymentMetrics", "Update", {})
    event["ResourceProperties"].update(version_parameter_property)

    # ACT
    lambda_handler(event, {})

    # ASSERT
    posted_request = mock_urlopen.call_args.args[0]
    usage_data = json.loads(urllib.parse.unquote(posted_request.data.decode("utf8")))
    assert usage_data["Version"] == expected_version
    mock_cfnresponse.assert_called_once_with(event, {}, SUCCESS, ANY)


@pytest.mark.parametrize("request_type", ["Create", "Update", "Delete"])
@patch("cfnresponse.send")
@patch("layer.metrics.Metrics.send_metrics")
@patch("deployment_metrics_custom_resource.SECURITY_HUB_CLIENT")
def test_send_metrics_securityhub_not_found(
    mock_securityhub, mock_send_metrics, mock_cfnresponse, request_type
):
    # ARRANGE
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
