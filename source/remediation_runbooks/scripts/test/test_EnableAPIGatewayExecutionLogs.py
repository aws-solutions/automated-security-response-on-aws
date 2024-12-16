# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import boto3
import botocore.session
import EnableAPIGatewayExecutionLogs as remediation
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup_rest_api(api_name, stage_name):
    client = boto3.client("apigateway", config=BOTO_CONFIG)
    create_api_response = client.create_rest_api(
        name=api_name,
    )
    api_id = create_api_response["id"]
    client.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId="my_deployment_id",
    )

    client.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {
                "op": "replace",
                "path": "/*/*/logging/loglevel",
                "value": "OFF",
            },
        ],
    )
    return api_id


def verify_stage_logging(api_id, stage_name, log_level):
    client = boto3.client("apigateway", config=BOTO_CONFIG)
    response = client.get_stage(restApiId=api_id, stageName=stage_name)
    for _, settings in response["methodSettings"].items():
        assert settings["loggingLevel"] == log_level


def setup_mock_websocket_api(mocker, api_id, stage_name, log_level):
    client = boto3.client("apigatewayv2", config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_response(
        "get_stage",
        {
            "RouteSettings": {
                "first": {
                    "DataTraceEnabled": True,
                    "DetailedMetricsEnabled": True,
                    "LoggingLevel": "OFF",
                },
                "second": {
                    "DataTraceEnabled": True,
                    "DetailedMetricsEnabled": True,
                    "LoggingLevel": log_level,
                },
                "third": {
                    "DataTraceEnabled": True,
                    "DetailedMetricsEnabled": True,
                    "LoggingLevel": "OFF",
                },
                "fourth": {
                    "DataTraceEnabled": True,
                    "DetailedMetricsEnabled": True,
                    "LoggingLevel": "OFF",
                },
            },
        },
        {"ApiId": api_id, "StageName": stage_name},
    )

    stubber.add_response(
        "update_stage",
        {},
        {
            "ApiId": api_id,
            "DefaultRouteSettings": {
                "LoggingLevel": log_level,
            },
            "RouteSettings": {
                "first": {"LoggingLevel": log_level},
                "third": {"LoggingLevel": log_level},
                "fourth": {"LoggingLevel": log_level},
            },
            "StageName": stage_name,
        },
    )
    mocker.patch(
        "EnableAPIGatewayExecutionLogs.connect_to_service", return_value=client
    )
    return stubber


@mock_aws
def test_handler_with_rest_api():
    api_name = "my-test-api"
    stage_name = "my-stage"
    log_level = "INFO"

    api_id = setup_rest_api(api_name, stage_name)

    response = remediation.handler(
        {
            "APIGatewayStageArnSuffix": f"/restapis/{api_id}/stages/{stage_name}",
            "LoggingLevel": log_level,
        },
        None,
    )

    verify_stage_logging(api_id, stage_name, log_level)
    assert response["ApiId"] == api_id
    assert response["StageName"] == stage_name
    assert response["Message"]


@mock_aws
def test_handler_with_nonexistent_rest_api():
    api_name = "my-test-api"
    stage_name = "my-stage"
    log_level = "INFO"

    with pytest.raises(Exception) as e:
        remediation.handler(
            {
                "APIGatewayStageArnSuffix": f"/restapis/{api_name}/stages/{stage_name}",
                "LoggingLevel": log_level,
            },
            None,
        )
    assert re.match(
        r"Encountered exception enabling execution logging for REST API", str(e.value)
    )


def test_handler_with_websocket_api(mocker):
    api_id = "my-test-api"
    stage_name = "my-stage"
    log_level = "INFO"

    stubber = setup_mock_websocket_api(mocker, api_id, stage_name, log_level)
    stubber.activate()
    response = remediation.handler(
        {
            "APIGatewayStageArnSuffix": f"/apis/{api_id}/stages/{stage_name}",
            "LoggingLevel": log_level,
        },
        None,
    )

    stubber.assert_no_pending_responses()
    stubber.deactivate()
    assert response["ApiId"] == api_id
    assert response["StageName"] == stage_name
    assert response["Message"]


def test_handler_with_websocket_api_error(mocker):
    api_id = "my-test-api"
    stage_name = "my-stage"
    log_level = "INFO"

    client = botocore.session.get_session().create_client(
        "apigatewayv2", config=BOTO_CONFIG
    )
    stubber = Stubber(client)
    stubber.add_client_error(
        "get_stage",
        service_error_code="ServiceException",
        service_message="Error",
    )
    mocker.patch(
        "EnableAPIGatewayExecutionLogs.connect_to_service", return_value=client
    )
    stubber.activate()

    with pytest.raises(Exception) as e:
        remediation.handler(
            {
                "APIGatewayStageArnSuffix": f"/apis/{api_id}/stages/{stage_name}",
                "LoggingLevel": log_level,
            },
            None,
        )
    assert re.match(
        r"Encountered exception enabling execution logging for WebSocket API",
        str(e.value),
    )
    stubber.deactivate()


def test_handler_with_invalid_arn_suffix():
    api_name = "my-test-api"
    stage_name = "my-stage"
    log_level = "INFO"

    with pytest.raises(Exception) as e:
        remediation.handler(
            {
                "APIGatewayStageArnSuffix": f"/something/{api_name}/stages/{stage_name}",
                "LoggingLevel": log_level,
            },
            None,
        )
    assert re.match(r"Encountered malformed API stage ARN", str(e.value))
