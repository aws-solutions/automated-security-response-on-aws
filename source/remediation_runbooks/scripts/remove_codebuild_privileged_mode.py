# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_codebuild():
    return boto3.client("codebuild", config=boto_config)


def lambda_handler(event, _):
    """
    Removes CodeBuild privileged mode from a project.

    `event` should have the following keys and values:
    `project_name`: the name of the codebuild project with privileged mode enabled.

    `context` is ignored
    """
    project_name = event["project_name"]

    project_attributes = get_project_info(project_name)

    initial_environment = project_attributes["projects"][0]["environment"]

    initial_environment["privilegedMode"] = False

    remove_privileged_mode(project_name, initial_environment)

    updated_project_attributes = get_project_info(project_name)

    privileged_status = updated_project_attributes["projects"][0]["environment"][
        "privilegedMode"
    ]

    if privileged_status is False:
        return {"privilegedMode": privileged_status}

    raise RuntimeError(
        f"ASR Remediation failed - {project_name} did not have privileged mode removed from project."
    )


def remove_privileged_mode(project_name, environment):
    """
    Removes privileged_status from CodeBuild Project
    """
    codebuild = connect_to_codebuild()
    try:
        codebuild.update_project(name=project_name, environment=environment)

    except Exception as e:
        exit("There was an error updating codebuild project: " + str(e))


def get_project_info(project_name):
    """
    Gets CodeBuild Project info
    """
    codebuild = connect_to_codebuild()
    try:
        project_attributes = codebuild.batch_get_projects(names=[project_name])
        return project_attributes

    except Exception as e:
        exit("Failed to get attributes of project: " + str(e))
