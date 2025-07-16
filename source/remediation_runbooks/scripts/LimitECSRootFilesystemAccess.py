# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


class Event(TypedDict):
    TaskDefinitionId: str


class Response(TypedDict):
    message: str
    status: str


def get_ecs_client():
    return boto3.client("ecs", config=boto_config)


def handler(event, _) -> Response:
    """
    Remediates ECS.5 Security Hub finding by creating a new
    revision for the non-compliant Task Definition with readonlyRootFilesystem.
    """
    try:
        task_definition_id = event["TaskDefinitionId"]

        task_definition = get_task_definition(task_definition_id)
        stripped_task_defintion = strip_task_definition(task_definition)

        set_readonly_root_filesystem(stripped_task_defintion)

        new_revision_arn = register_new_revision(stripped_task_defintion)
        return {
            "message": f"Successfully registered new task definition {new_revision_arn}.",
            "status": "Success",
        }
    except Exception as e:
        raise RuntimeError(f"Failed to Limit Root Filesystem access: {str(e)}")


def get_task_definition(task_definition_id: str) -> dict:
    ecs_client = get_ecs_client()
    task_definition = ecs_client.describe_task_definition(
        taskDefinition=task_definition_id,
        include=[
            "TAGS",
        ],
    )
    return task_definition["taskDefinition"]


def strip_task_definition(task_definition: dict) -> dict:
    """
    Creates a new dictionary with only the keys accepted by the RegisterTaskDefinition API.
    """
    accepted_keys = set(task_definition.keys()) - {
        "taskDefinitionArn",
        "revision",
        "compatibilities",
        "status",
        "requiresAttributes",
        "registeredAt",
        "registeredBy",
    }
    return {key: task_definition[key] for key in accepted_keys}


def set_readonly_root_filesystem(task_definition: dict):
    container_definitions = task_definition["containerDefinitions"]
    for container_definition in container_definitions:
        container_definition["readonlyRootFilesystem"] = True


def register_new_revision(task_definition: dict) -> str:
    ecs_client = get_ecs_client()
    response = ecs_client.register_task_definition(**task_definition)
    return response["taskDefinition"]["taskDefinitionArn"]
