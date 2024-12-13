# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, List, TypedDict

if TYPE_CHECKING:
    from mypy_boto3_apigateway import APIGatewayClient
else:
    APIGatewayClient = object

import boto3
from botocore.config import Config


def connect_to_apigateway(boto_config: Config) -> APIGatewayClient:
    return boto3.client("apigateway", config=boto_config)


class MethodSettings(TypedDict):
    ResourcePath: str
    HttpMethod: str


class Event(TypedDict):
    APIGatewayStageArn: str
    StageName: str
    MethodSettings: List[MethodSettings]


def enable_data_encryption(event: Event, _):
    boto_config = Config(retries={"mode": "standard"})
    apigateway = connect_to_apigateway(boto_config)

    try:
        api_id = event["APIGatewayStageArn"].split("/")[2]

        for method_settings in event["MethodSettings"]:
            resource_path = method_settings["ResourcePath"]
            http_method = method_settings["HttpMethod"]

            apigateway.update_stage(
                restApiId=api_id,
                stageName=event["StageName"],
                patchOperations=[
                    {
                        "op": "replace",
                        "path": f"/{resource_path}/{http_method}/caching/dataEncrypted",
                        "value": "true",
                    },
                ],
            )

        return {
            "message": "Successfully enabled cache data encryption.",
            "status": "Success",
        }
    except Exception as e:
        raise RuntimeError(f"Encountered error setting cache data encryption: {str(e)}")
