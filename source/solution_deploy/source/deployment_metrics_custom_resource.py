# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Custom resource provider that handles deployment actions"""

import json
from logging import basicConfig, getLevelName, getLogger
from os import getenv

import cfnresponse
from layer.metrics import Metrics

# fmt: off
basicConfig(level=getLevelName(getenv("LOG_LEVEL", "INFO")))  # NOSONAR This configures logging based on the environment variable that is set.
# fmt: on
logger = getLogger(__name__)


def lambda_handler(event, context):
    response_data: dict[str, str] = {}
    logger.debug(f"received event: {json.dumps(event)}")

    try:
        properties = event.get("ResourceProperties", {})
        logger.info(json.dumps(properties))

        if event.get("ResourceType", {}) == "Custom::DeploymentMetrics":
            send_deployment_metrics(properties, event.get("RequestType", {}))

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


def send_deployment_metrics(properties, request_type):
    metrics_obj = Metrics()

    stack_parameters = properties.get("StackParameters", {})
    metrics_data = {
        "Event": f"Solution{request_type}",
        "RequestType": request_type,
        **stack_parameters,  # Spread all stack parameters directly
    }
    metrics_obj.send_metrics(metrics_data)
