# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re

import boto3
import pytest
from botocore.config import Config
from EnableAPIGatewayCacheDataEncryption import Event, enable_data_encryption
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup():
    rest_api_id = create_test_api("test_api")
    root_resource_id = get_root_resource_id(rest_api_id)
    resource_id = create_test_resource(rest_api_id, root_resource_id, "test")
    create_resource_method(rest_api_id, resource_id, "GET")
    create_test_resource_integration(rest_api_id, resource_id, "GET")
    resource_id = create_test_resource(rest_api_id, resource_id, "test2")
    create_resource_method(rest_api_id, resource_id, "GET")
    create_test_resource_integration(rest_api_id, resource_id, "GET")
    create_test_deployment(rest_api_id, "test")

    set_cache_encryption(rest_api_id, "test", "*", "*", "False")
    set_cache_encryption(rest_api_id, "test", "test", "GET", "False")
    set_cache_encryption(rest_api_id, "test", "test2", "GET", "False")

    return rest_api_id


def create_test_api(name):
    apigateway_client = boto3.client("apigateway", config=BOTO_CONFIG)
    response = apigateway_client.create_rest_api(name=name, description="test")
    return response["id"]


def get_root_resource_id(rest_api_id):
    apigateway_client = boto3.client("apigateway", config=BOTO_CONFIG)
    response = apigateway_client.get_resources(restApiId=rest_api_id)
    for item in response["items"]:
        if item["path"] == "/":
            return item["id"]


def create_test_resource(rest_api_id, parent_id, path_part):
    apigateway_client = boto3.client("apigateway", config=BOTO_CONFIG)
    response = apigateway_client.create_resource(
        restApiId=rest_api_id,
        parentId=parent_id,
        pathPart=path_part,
    )
    return response["id"]


def create_resource_method(rest_api_id, resource_id, http_method):
    apigateway_client = boto3.client("apigateway", config=BOTO_CONFIG)
    apigateway_client.put_method(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        authorizationType="NONE",
    )


def create_test_resource_integration(rest_api_id, resource_id, http_method):
    apigateway_client = boto3.client("apigateway", config=BOTO_CONFIG)
    apigateway_client.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )


def create_test_deployment(rest_api_id, stage_name):
    apigateway_client = boto3.client("apigateway", config=BOTO_CONFIG)
    response = apigateway_client.create_deployment(
        restApiId=rest_api_id,
        stageName=stage_name,
        description="test",
        cacheClusterEnabled=True,
    )
    return response["id"]


def set_cache_encryption(api_id, stage_name, resource_path, http_method, state):
    apigateway = boto3.client("apigateway", config=BOTO_CONFIG)
    apigateway.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[
            {
                "op": "replace",
                "path": f"/{resource_path}/{http_method}/caching/dataEncrypted",
                "value": state,
            },
        ],
    )


@mock_aws
def test_enable_data_encryption_success():
    rest_api_id = setup()

    event: Event = {
        "APIGatewayStageArn": f"arn:aws:apigateway:us-east-1::/restapis/{rest_api_id}/stages/stage2",
        "StageName": "test",
        "MethodSettings": [
            {"ResourcePath": "*", "HttpMethod": "*"},
            {"ResourcePath": "test", "HttpMethod": "GET"},
            {"ResourcePath": "test2", "HttpMethod": "GET"},
        ],
    }

    apigateway_client = boto3.client("apigateway", config=BOTO_CONFIG)
    stage = apigateway_client.get_stage(restApiId=rest_api_id, stageName="test")
    assert stage["methodSettings"]["*/*"]["cacheDataEncrypted"] is False
    assert stage["methodSettings"]["test/GET"]["cacheDataEncrypted"] is False
    assert stage["methodSettings"]["test2/GET"]["cacheDataEncrypted"] is False

    enable_data_encryption(event, None)

    stage = apigateway_client.get_stage(restApiId=rest_api_id, stageName="test")
    assert stage["methodSettings"]["*/*"]["cacheDataEncrypted"] is True
    assert stage["methodSettings"]["test/GET"]["cacheDataEncrypted"] is True
    assert stage["methodSettings"]["test2/GET"]["cacheDataEncrypted"] is True


@mock_aws
def test_invalid_event():
    event: Event = {
        "APIGatewayStageArn": "badarn",
        "StageName": "test",
        "MethodSettings": [
            {"ResourcePath": "*", "HttpMethod": "*"},
            {"ResourcePath": "test", "HttpMethod": "GET"},
            {"ResourcePath": "test2", "HttpMethod": "GET"},
        ],
    }

    with pytest.raises(Exception) as e:
        enable_data_encryption(event, None)
    assert re.match(r"Encountered error setting cache data encryption:", str(e.value))
