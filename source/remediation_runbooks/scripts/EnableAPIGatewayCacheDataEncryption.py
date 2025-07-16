# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, TypedDict

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


def enable_data_encryption(event: Event, _):
    boto_config = Config(retries={"mode": "standard"})
    apigateway = connect_to_apigateway(boto_config)

    try:
        api_id = event["APIGatewayStageArn"].split("/")[2]
        stage_name = event["APIGatewayStageArn"].split("/")[4]
        print(api_id, stage_name)
        stage_details = apigateway.get_stage(restApiId=api_id, stageName=stage_name)
        for method_key, method_value in stage_details["methodSettings"].items():
            apigateway.update_stage(
                restApiId=api_id,
                stageName=stage_name,
                patchOperations=[
                    {
                        "op": "replace",
                        "path": f"/{method_key}/caching/dataEncrypted",
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
