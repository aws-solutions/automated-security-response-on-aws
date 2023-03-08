# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Custom resource provider that waits for a specified time, then returns success"""

from os import getenv
import json
from logging import basicConfig, getLevelName, getLogger
from time import sleep
import cfnresponse

basicConfig(level=getLevelName(getenv("LOG_LEVEL", "INFO")))
logger = getLogger(__name__)


class InvalidRequest(Exception):
    """Invalid wait request"""


def wait_seconds(wait: float):
    """Wait for `wait` seconds"""
    sleep(wait)


def lambda_handler(event, context):
    """Handle the Lambda request for a wait"""
    response_data = {}

    try:
        properties = event.get("ResourceProperties", {})
        logger.info(json.dumps(properties))

        wait_create = float(properties["CreateIntervalSeconds"])
        wait_update = float(properties["UpdateIntervalSeconds"])
        wait_delete = float(properties["DeleteIntervalSeconds"])

        request_type = event["RequestType"]
        if request_type == "Create":
            logger.info("Create, waiting %f seconds", wait_create)
            wait_seconds(wait_create)
        elif request_type == "Update":
            logger.info("Update, waiting %f seconds", wait_update)
            wait_seconds(wait_update)
        elif request_type == "Delete":
            logger.info("Delete, waiting %f seconds", wait_delete)
            wait_seconds(wait_delete)
        else:
            raise InvalidRequest(f"Invalid request type {request_type}")
        logger.info("Success")

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
