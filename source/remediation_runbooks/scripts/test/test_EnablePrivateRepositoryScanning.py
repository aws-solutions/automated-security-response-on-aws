# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `EnablePrivateRepositoryScanning` remediation script"""

import boto3
from botocore.config import Config
from EnablePrivateRepositoryScanning import lambda_handler
from moto import mock_aws


@mock_aws
def test_enable_private_repo_scanning():
    BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

    ecr = boto3.client("ecr", config=BOTO_CONFIG)

    # Create private repository with scannning disabled
    repository = ecr.create_repository(
        repositoryName="test-ecr.1-repo",
        imageScanningConfiguration={"scanOnPush": False},
    )

    # Get the repository name
    repository_name = repository["repository"]["repositoryName"]
    event = {"RepositoryName": repository_name}

    # Run remediation script
    lambda_handler(event, {})

    # Get the updated repository
    updated_repository = ecr.describe_repositories(repositoryNames=[repository_name])

    # Verify the repository now has scanning enabled
    assert updated_repository["repositories"][0]["imageScanningConfiguration"][
        "scanOnPush"
    ]
