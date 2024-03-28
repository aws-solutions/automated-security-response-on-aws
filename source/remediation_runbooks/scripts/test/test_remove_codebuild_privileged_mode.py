# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `remove_codebuild_privileged_mode` remediation script"""

from datetime import datetime
from unittest.mock import patch

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from remove_codebuild_privileged_mode import lambda_handler


def test_remove_codebuild_privileged_mode(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
    codebuild = boto3.client("codebuild", config=BOTO_CONFIG)
    stub_codebuild = Stubber(codebuild)
    clients = {"codebuild": codebuild}

    project_name = "TestProject"

    stub_codebuild.add_response(
        "batch_get_projects", describedCodeBuildProject, {"names": [project_name]}
    )

    stub_codebuild.add_response(
        "update_project",
        {},
        {"name": project_name, "environment": edited_environment},
    )

    describedCodeBuildProject["projects"][0]["environment"] = edited_environment

    stub_codebuild.add_response(
        "batch_get_projects", describedCodeBuildProject, {"names": [project_name]}
    )

    stub_codebuild.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {"project_name": project_name}
        response = lambda_handler(event, {})
        assert response == {"privilegedMode": edited_environment["privilegedMode"]}


describedCodeBuildProject = {
    "projects": [
        {
            "name": "TestProject",
            "arn": "arn",
            "description": "description",
            "source": {"type": "BITBUCKET"},
            "secondarySources": [{"type": "BITBUCKET"}],
            "sourceVersion": "test",
            "secondarySourceVersions": [{"sourceIdentifier": "", "sourceVersion": ""}],
            "artifacts": {"type": "CODEPIPELINE"},
            "secondaryArtifacts": [{"type": "CODEPIPELINE"}],
            "cache": {"type": "LOCAL"},
            "environment": {
                "type": "WINDOWS_CONTAINER",
                "image": "test",
                "computeType": "BUILD_GENERAL1_2XLARGE",
                "environmentVariables": [],
                "privilegedMode": True,
                "certificate": "test",
                "registryCredential": {
                    "credential": "test",
                    "credentialProvider": "SECRETS_MANAGER",
                },
                "imagePullCredentialsType": "CODEBUILD",
            },
            "serviceRole": "test",
            "timeoutInMinutes": 5,
            "queuedTimeoutInMinutes": 5,
            "encryptionKey": "test",
            "tags": [{"key": "test", "value": "test"}],
            "created": datetime(2015, 1, 1),
            "lastModified": datetime(2015, 1, 1),
            "webhook": {
                "url": "test",
                "payloadUrl": "test",
                "secret": "test",
                "branchFilter": "test",
                "filterGroups": [],
                "buildType": "BUILD",
                "lastModifiedSecret": datetime(2015, 1, 1),
            },
            "vpcConfig": {
                "vpcId": "test",
                "subnets": ["test"],
                "securityGroupIds": ["test"],
            },
            "badge": {"badgeEnabled": False, "badgeRequestUrl": ""},
            "logsConfig": {
                "cloudWatchLogs": {"status": "ENABLED"},
                "s3Logs": {"status": "DISABLED"},
            },
            "fileSystemLocations": [
                {
                    "identifier": "",
                    "mountOptions": "",
                    "mountPoint": "",
                    "location": "",
                    "type": "EFS",
                }
            ],
            "buildBatchConfig": {
                "serviceRole": "test",
                "combineArtifacts": False,
                "timeoutInMins": 1,
                "restrictions": {
                    "maximumBuildsAllowed": 1,
                    "computeTypesAllowed": [
                        "string",
                    ],
                },
                "batchReportMode": "REPORT_INDIVIDUAL_BUILDS",
            },
            "concurrentBuildLimit": 1,
            "projectVisibility": "PRIVATE",
            "publicProjectAlias": "test",
            "resourceAccessRole": "test",
        }
    ],
    "projectsNotFound": ["notFound"],
    "ResponseMetadata": {
        "HostId": "test",
        "RequestId": "test",
        "HTTPStatusCode": 404,
        "HTTPHeaders": {"test": "test"},
        "RetryAttempts": 1,
    },
}

edited_environment = {
    "type": "WINDOWS_CONTAINER",
    "image": "test",
    "computeType": "BUILD_GENERAL1_2XLARGE",
    "environmentVariables": [],
    "privilegedMode": False,
    "certificate": "test",
    "registryCredential": {
        "credential": "test",
        "credentialProvider": "SECRETS_MANAGER",
    },
    "imagePullCredentialsType": "CODEBUILD",
}
