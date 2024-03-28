# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ecr():
    return boto3.client("ecr", config=boto_config)


def lambda_handler(event, _):
    repository_name = event["RepositoryName"]
    ecr = connect_to_ecr()

    response = ecr.put_image_scanning_configuration(
        repositoryName=repository_name, imageScanningConfiguration={"scanOnPush": True}
    )

    return response
