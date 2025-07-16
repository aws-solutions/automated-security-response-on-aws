# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
import pytest
from botocore.config import Config
from LimitECSRootFilesystemAccess import handler
from moto import mock_aws

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=REGION)


@mock_aws
def test_handler_happy_path():
    ecs_client = boto3.client("ecs", region_name=REGION)
    response = ecs_client.register_task_definition(
        family="test-task",
        containerDefinitions=[
            {
                "name": "test-container",
                "image": "test-image",
                "memory": 123,
                "cpu": 123,
                "readonlyRootFilesystem": False,
            }
        ],
    )

    task_definition_arn = response["taskDefinition"]["taskDefinitionArn"]
    task_definition_id = task_definition_arn.split("/")[-1]

    event = {"TaskDefinitionId": task_definition_id}
    result = handler(event, None)

    assert (
        result["status"] == "Success"
    )  # Changed from statusCode to match actual response
    assert "Successfully registered new task definition" in result["message"]


@mock_aws
def test_handler_missing_task_definition():
    event = {}
    with pytest.raises(RuntimeError):
        handler(event, None)


@mock_aws
def test_handler_nonexistent_task():
    event = {"TaskDefinitionId": "nonexistent-task:1"}
    with pytest.raises(RuntimeError):
        handler(event, None)


@mock_aws
def test_handler_multiple_containers():
    ecs_client = boto3.client("ecs", region_name=REGION)
    response = ecs_client.register_task_definition(
        family="multi-container-task",
        containerDefinitions=[
            {
                "name": "container1",
                "image": "image1",
                "memory": 123,
                "cpu": 123,
                "readonlyRootFilesystem": False,
            },
            {
                "name": "container2",
                "image": "image2",
                "memory": 123,
                "cpu": 123,
                "readonlyRootFilesystem": False,
            },
        ],
    )

    task_definition_arn = response["taskDefinition"]["taskDefinitionArn"]
    task_definition_id = task_definition_arn.split("/")[-1]

    event = {"TaskDefinitionId": task_definition_id}
    result = handler(event, None)

    assert result["status"] == "Success"
    assert "Successfully registered new task definition" in result["message"]

    # Verify all containers in new task definition have readonly filesystem
    new_task_def = ecs_client.describe_task_definition(
        taskDefinition=task_definition_id.split(":")[0]
    )["taskDefinition"]

    for container in new_task_def["containerDefinitions"]:
        assert container["readonlyRootFilesystem"] is True
