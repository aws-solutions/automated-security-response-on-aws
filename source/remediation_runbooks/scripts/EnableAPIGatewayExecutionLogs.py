# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import logging
import re
import traceback
from typing import Any, TypedDict

import boto3
from botocore.config import Config

logger = logging.getLogger()
boto_config = Config(retries={"mode": "standard"})


def connect_to_service(client: str) -> Any:
    return boto3.client(client, config=boto_config)


class Event(TypedDict):
    APIGatewayStageArnSuffix: str
    LoggingLevel: str  # Security Hub parameter


class Response(TypedDict):
    Message: str
    LoggingLevel: str
    ApiId: str
    StageName: str
    ApiType: str  # REST or WebSocket


class APIStageDetails(TypedDict):
    StageName: str
    ApiId: str


def handler(event: Event, _):
    stage_arn_suffix = event["APIGatewayStageArnSuffix"]
    logging_level = event["LoggingLevel"]

    stage_is_rest_api = is_rest_api(stage_arn_suffix)
    api_stage_details: APIStageDetails = extract_details_from_arn_suffix(
        stage_arn_suffix, stage_is_rest_api
    )

    if stage_is_rest_api:
        enable_rest_execution_logging(api_stage_details, logging_level)
    else:
        enable_websocket_execution_logging(api_stage_details, logging_level)

    stage_name = api_stage_details["StageName"]
    api_id = api_stage_details["ApiId"]
    return {
        "Message": f"successfully enabled execution logging at {logging_level} for stage {stage_name} in API {api_id}",
        "LoggingLevel": logging_level,
        "ApiId": api_id,
        "StageName": stage_name,
        "ApiType": "REST" if stage_is_rest_api else "WebSocket",
    }


def is_rest_api(arn_suffix: str) -> bool:
    if arn_suffix.startswith("/restapis/"):
        return True
    return False


def extract_details_from_arn_suffix(arn_suffix: str, is_rest: bool) -> APIStageDetails:
    regex_pattern = (
        r"^/restapis/(?P<api_id>.+)/stages/(?P<stage_name>.+)$"
        if is_rest
        else r"^/apis/(?P<api_id>.+)/stages/(?P<stage_name>.+)$"
    )
    match = re.fullmatch(regex_pattern, arn_suffix)

    if (
        not match
        or "api_id" not in match.groupdict()
        or "stage_name" not in match.groupdict()
    ):
        raise RuntimeError(
            f"Encountered malformed API stage ARN: {arn_suffix}\n Expected to be a REST or WebSocket API of the form "
            f"/apis/api-id/stages/stage-name OR /restapis/api-id/stages/stage-name"
        )
    return {"ApiId": match.group("api_id"), "StageName": match.group("stage_name")}


def enable_rest_execution_logging(
    stage_details: APIStageDetails, log_level: str
) -> None:
    rest_apigateway_client = connect_to_service("apigateway")
    api_id = stage_details["ApiId"]
    stage_name = stage_details["StageName"]
    try:
        rest_apigateway_client.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {
                    "op": "replace",
                    "path": "/*/*/logging/loglevel",
                    "value": log_level,
                },
            ],
        )

        logger.info(
            f"Set log level to {log_level} for all routes in stage {stage_name} in REST API {api_id}"
        )
    except Exception as e:
        raise RuntimeError(
            f"Encountered exception enabling execution logging for REST API stage {stage_name} in API {api_id}: {str(e)}\n\n{traceback.format_exc()}"
        )


def enable_websocket_execution_logging(
    stage_details: APIStageDetails, log_level: str
) -> None:
    websocket_apigateway_client = connect_to_service("apigatewayv2")
    api_id = stage_details["ApiId"]
    stage_name = stage_details["StageName"]
    try:
        response = websocket_apigateway_client.get_stage(
            ApiId=api_id, StageName=stage_name
        )  # fetch all routes in this stage that don't meet logging requirements
        routes_to_update = [
            route
            for route, route_setting in response["RouteSettings"].items()
            if "LoggingLevel" not in route_setting
            or route_setting["LoggingLevel"] != log_level
        ]
        route_settings = {
            route: {"LoggingLevel": log_level} for route in routes_to_update
        }

        websocket_apigateway_client.update_stage(
            ApiId=api_id,
            DefaultRouteSettings={
                "LoggingLevel": log_level,
            },
            RouteSettings=route_settings,
            StageName=stage_name,
        )

        updated_routes = [*routes_to_update, "default"]
        logger.info(
            f"Updated the following routes to log level {log_level} in stage {stage_name} in WebSocket API {api_id}: {str(updated_routes)}"
        )

    except Exception as e:
        raise RuntimeError(
            f"Encountered exception enabling execution logging for WebSocket API stage {stage_name} in API {api_id}: {str(e)}\n\n{traceback.format_exc()}"
        )
