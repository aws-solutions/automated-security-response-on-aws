# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from logging import basicConfig, getLevelName, getLogger
from os import getenv

import boto3
import cfnresponse

# fmt: off
basicConfig(level=getLevelName(getenv("LOG_LEVEL", "INFO")))  # NOSONAR This configures logging based on the environment variable that is set.
# fmt: on
logger = getLogger(__name__)


def lambda_handler(event, context):
    response_data: dict[str, str] = {}

    try:
        request_type = event["RequestType"]

        if request_type in ["Create", "Update"]:
            ssm = boto3.client("ssm")
            logger.info("Enabling SSM Adaptive Concurrency")
            ssm.update_service_setting(
                SettingId="/ssm/automation/enable-adaptive-concurrency",
                SettingValue="True",
            )
            logger.info("SSM Adaptive Concurrency enabled successfully")
            response_data["Message"] = "Adaptive concurrency enabled"

    except Exception as exc:
        logger.warning(
            "Failed to enable adaptive concurrency, continuing deployment: %s",
            exc,
        )
        response_data["adaptive_concurrency_enabled"] = "false"
        response_data["Message"] = f"Adaptive concurrency not enabled: {exc}"

    cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)
