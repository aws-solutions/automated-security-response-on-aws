# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Custom resource provider that handles deployment actions"""

import json
from logging import basicConfig, getLevelName, getLogger
from os import getenv

import boto3
import cfnresponse
from botocore.exceptions import ClientError
from layer.metrics import Metrics

# fmt: off
basicConfig(level=getLevelName(getenv("LOG_LEVEL", "INFO")))  # NOSONAR This configures logging based on the environment variable that is set.
# fmt: on
logger = getLogger(__name__)


def is_securityhub_v2_enabled() -> bool:
    securityhub_client = boto3.client("securityhub")
    try:
        response = securityhub_client.describe_security_hub_v2()
        return "HubV2Arn" in response
    except ClientError as error:
        if error.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.debug("Security Hub v2 is not enabled.")
    except Exception as e:
        logger.debug(
            f"An unexpected error occurred while checking Security Hub v2 configuration: {e}"
        )
    return False


def lambda_handler(event, context):
    response_data: dict[str, str] = {}
    logger.debug(f"received event: {json.dumps(event)}")

    try:
        properties = event.get("ResourceProperties", {})
        logger.info(json.dumps(properties))

        securityhub_v2_enabled = is_securityhub_v2_enabled()

        if event.get("ResourceType", {}) == "Custom::DeploymentMetrics":
            send_deployment_metrics(
                properties, event.get("RequestType", {}), securityhub_v2_enabled
            )

        response_data["securityhub_v2_enabled"] = str(securityhub_v2_enabled)
        cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)
    except Exception as exc:
        logger.exception(exc)
        cfnresponse.send(
            event,
            context,
            cfnresponse.FAILED,
            response_data,
            reason=str(exc),
        )


def send_deployment_metrics(properties, request_type, securityhub_v2_enabled):
    metrics_obj = Metrics()

    stack_parameters = properties.get("StackParameters", {})
    metrics_data = {
        "Event": f"Solution{request_type}",
        "RequestType": request_type,
        "SecurityHubV2Enabled": securityhub_v2_enabled,
        **stack_parameters,  # Spread all stack parameters directly
    }
    metrics_obj.send_metrics(metrics_data)
