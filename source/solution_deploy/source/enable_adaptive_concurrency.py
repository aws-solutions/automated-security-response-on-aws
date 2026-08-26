# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from logging import basicConfig, getLevelName, getLogger
from os import getenv

import boto3
import cfnresponse
from botocore.config import Config

# fmt: off
basicConfig(level=getLevelName(getenv("LOG_LEVEL", "INFO")))  # NOSONAR This configures logging based on the environment variable that is set.
# fmt: on
logger = getLogger(__name__)

# Explicit timeouts bound each network call so a hung endpoint cannot stall the
# custom-resource Lambda for its full timeout; standard retries add headroom.
BOTO_CONFIG = Config(retries={"mode": "standard"}, connect_timeout=5, read_timeout=10)

# Reusable client initialized at module load (construction time of the Lambda) so
# it is shared across invocations of the warm execution environment.
SSM_CLIENT = boto3.client("ssm", config=BOTO_CONFIG)


def lambda_handler(event, context):
    response_data: dict[str, str] = {}

    try:
        request_type = event["RequestType"]

        if request_type in ["Create"]:
            logger.info("Enabling SSM Adaptive Concurrency")
            SSM_CLIENT.update_service_setting(
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
