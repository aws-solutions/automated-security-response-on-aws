# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
import traceback
from typing import Any, List, TypedDict

import boto3
import cfnresponse
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})
logger = logging.getLogger()
logger.setLevel("INFO")

# Determine if we are executing locally or in Lambda
controls_file_path = (
    "controls.json"
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    else "../common/controls.json"
)
# Load implemented control ids per playbook
controls_file = open(controls_file_path)
CONTROL_IDS = json.load(controls_file)


class ResourceProperties(TypedDict):
    SecurityStandard: str
    SecurityStandardVersion: str


class Event(TypedDict):
    ResourceProperties: ResourceProperties
    ResourceType: str


class Response(TypedDict):
    EnabledRules: List[str]
    FailedToEnableRules: List[str]


def connect_to_service(service: str) -> Any:
    return boto3.client(service, config=boto_config)


def lambda_handler(event: Event, context: Any) -> None:
    try:
        properties = event["ResourceProperties"]
        logger.info(json.dumps(properties))

        security_standard = event["ResourceProperties"]["SecurityStandard"]
        security_standard_version = event["ResourceProperties"][
            "SecurityStandardVersion"
        ]
        security_standard_version_stripped = security_standard_version.replace(".", "")

        security_standard_long_name = (
            f"{security_standard}{security_standard_version_stripped}"
        )

        enabled_rules = []
        failed_rules = []
        for control_id in CONTROL_IDS[security_standard_long_name]:
            response = enable_rule(
                f"{security_standard}_{security_standard_version}_{control_id}_AutoTrigger"
            )
            if response == "Success":
                enabled_rules.append(control_id)
            else:
                failed_rules.append(control_id)

        logger.info(f"Enabled Rules: {str(enabled_rules)}")
        logger.info(f"Failed Rules: {str(failed_rules)}")

        cfn_response = (
            cfnresponse.SUCCESS if len(failed_rules) == 0 else cfnresponse.FAILED
        )
        failed_reason = (
            f"Failed to enable rules: {str(failed_rules)}" if failed_rules else None
        )

        cfnresponse.send(event, context, cfn_response, {}, reason=failed_reason)
    except Exception as exc:
        logger.exception(exc)
        cfnresponse.send(
            event,
            context,
            cfnresponse.FAILED,
            {},
            reason=str(exc),
        )


def enable_rule(rule_name: str) -> str:
    eventbridge_client = connect_to_service("events")
    try:
        eventbridge_client.enable_rule(
            Name=rule_name,
        )
        logger.info(f"Enabled {rule_name}")
        return "Success"
    except Exception as e:
        logger.error(f"Encountered exception when enabling rule {rule_name}: {str(e)}")
        logger.debug(traceback.format_exc())
        return "Failed"
