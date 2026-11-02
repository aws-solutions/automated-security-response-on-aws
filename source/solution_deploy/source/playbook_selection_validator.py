# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fails the stack when the playbook selection cannot remediate the account's control
findings under its Security Hub consolidated control findings setting."""

from __future__ import annotations

from collections.abc import Mapping
from logging import getLogger
from os import getenv
from typing import TYPE_CHECKING, Literal, TypedDict

import boto3
import cfnresponse
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.data_classes import (
        CloudFormationCustomResourceEvent,
    )
    from aws_lambda_powertools.utilities.typing import LambdaContext
    from mypy_boto3_cloudformation.client import CloudFormationClient

logger = getLogger(__name__)
# basicConfig is a no-op in Lambda, whose runtime has already configured the root logger.
# fmt: off
logger.setLevel(getenv("LOG_LEVEL", "INFO"))  # NOSONAR This configures logging based on the environment variable that is set.
# fmt: on

# A stable ID keeps the forced update on each template upgrade from being treated as a replacement.
PHYSICAL_RESOURCE_ID = "PlaybookSelectionValidator"

BOTO_CONFIG = Config(retries={"mode": "standard"}, connect_timeout=5, read_timeout=10)
SECURITY_HUB_CLIENT = boto3.client("securityhub", config=BOTO_CONFIG)
CLOUDFORMATION_CLIENT: CloudFormationClient = boto3.client(
    "cloudformation", config=BOTO_CONFIG
)

YesNo = Literal["yes", "no"]
ControlFindingGenerator = Literal["SECURITY_CONTROL", "STANDARD_CONTROL"]

SECURITY_HUB_NOT_ENABLED_MESSAGE = (
    "Security Hub is not enabled in this account and Region. "
    "Enable Security Hub before deploying ASR."
)


class ValidationRequest(TypedDict):
    security_control_playbook_selection: YesNo
    standard_playbook_selection: YesNo
    is_security_hub_required: bool


class PlaybookSelectionError(Exception):
    """The deployment cannot proceed; the message is the reason CloudFormation shows."""


def lambda_handler(
    event: CloudFormationCustomResourceEvent, context: LambdaContext
) -> None:
    try:
        failure_reason = get_failure_reason(event)
    # An unanswered custom resource hangs the stack for an hour, so every error is reported.
    except Exception as error:  # NOSONAR
        logger.exception("Playbook selection validation failed unexpectedly")
        failure_reason = f"Playbook selection validation failed unexpectedly: {error}"

    if failure_reason:
        logger.error(failure_reason)
        cfnresponse.send(
            event,
            context,
            cfnresponse.FAILED,
            {},
            PHYSICAL_RESOURCE_ID,
            reason=failure_reason,
        )
    else:
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, PHYSICAL_RESOURCE_ID)


def get_failure_reason(event: CloudFormationCustomResourceEvent) -> str | None:
    if event["RequestType"] == "Delete":
        return None
    # Checked before the properties, because a rollback can re-send properties an older template set.
    if is_stack_rolling_back(event["StackId"]):
        logger.info("Stack is rolling back; skipping playbook selection validation")
        return None
    try:
        request = validate_event(event)
        generator = get_control_finding_generator()
        if generator is None:
            if request["is_security_hub_required"]:
                return SECURITY_HUB_NOT_ENABLED_MESSAGE
            # Member stacks often reach a Region through a StackSet before Security Hub is enabled there.
            logger.warning(
                "Security Hub is not enabled in this account and Region, so the playbook "
                "selection check is skipped. It runs again on the next template upgrade."
            )
            return None
        return check_selection_remediates(request, generator)
    except PlaybookSelectionError as error:
        return str(error)


def validate_event(event: CloudFormationCustomResourceEvent) -> ValidationRequest:
    properties = event["ResourceProperties"]
    return ValidationRequest(
        security_control_playbook_selection=validate_yes_no(
            properties, "SecurityControlPlaybookSelected"
        ),
        standard_playbook_selection=validate_yes_no(
            properties, "StandardPlaybookSelected"
        ),
        is_security_hub_required=validate_yes_no(properties, "SecurityHubRequired")
        == "yes",
    )


def validate_yes_no(properties: Mapping[str, object], property_name: str) -> YesNo:
    value = properties.get(property_name)
    if value == "yes":
        return "yes"
    if value == "no":
        return "no"
    raise PlaybookSelectionError(
        f"{property_name} must be 'yes' or 'no', got {value!r}"
    )


def is_stack_rolling_back(stack_id: str) -> bool:
    """Rollback re-sends the previous properties, which may no longer be valid; checking them
    again would fail the rollback and leave the stack in UPDATE_ROLLBACK_FAILED."""
    try:
        stacks = CLOUDFORMATION_CLIENT.describe_stacks(StackName=stack_id)["Stacks"]
    except (ClientError, BotoCoreError) as error:
        logger.warning(
            "Could not read the stack status, validating as normal: %s", error
        )
        return False
    return bool(stacks) and stacks[0]["StackStatus"].endswith("ROLLBACK_IN_PROGRESS")


def get_control_finding_generator() -> ControlFindingGenerator | None:
    """Returns None when Security Hub is not enabled in this account and Region."""
    try:
        generator: object = SECURITY_HUB_CLIENT.describe_hub()[
            "ControlFindingGenerator"
        ]
    except ClientError as error:
        if error.response["Error"]["Code"] == "InvalidAccessException":
            return None
        raise PlaybookSelectionError(
            f"Could not read the Security Hub settings: {error}"
        ) from error
    except BotoCoreError as error:
        raise PlaybookSelectionError(
            f"Could not read the Security Hub settings: {error}"
        ) from error
    if generator == "SECURITY_CONTROL":
        return "SECURITY_CONTROL"
    if generator == "STANDARD_CONTROL":
        return "STANDARD_CONTROL"
    raise PlaybookSelectionError(
        f"Unexpected Security Hub ControlFindingGenerator value: {generator!r}"
    )


def check_selection_remediates(
    request: ValidationRequest, generator: ControlFindingGenerator
) -> str | None:
    is_security_control_selected = (
        request["security_control_playbook_selection"] == "yes"
    )
    is_standard_selected = request["standard_playbook_selection"] == "yes"
    if generator == "SECURITY_CONTROL" and not is_security_control_selected:
        return (
            "Consolidated control findings are turned on in Security Hub "
            "(ControlFindingGenerator is SECURITY_CONTROL) in this account and Region, "
            "and only the Security Control (SC) playbook remediates them. "
            "Set the Security Control (SC) playbook parameter to yes."
        )
    if generator == "STANDARD_CONTROL" and not is_standard_selected:
        return (
            "Consolidated control findings are turned off in Security Hub "
            "(ControlFindingGenerator is STANDARD_CONTROL) in this account and Region, "
            "and the Security Control (SC) playbook does not remediate them. "
            "Set the playbook parameter to yes for each security standard enabled in Security Hub."
        )
    if is_security_control_selected and is_standard_selected:
        logger.warning(
            "The Security Control (SC) playbook is deployed together with security standard "
            "playbooks. Control findings use only the playbook that matches the Security Hub "
            "consolidated control findings setting (%s), so the control runbooks of the "
            "playbooks that do not match stay unused.%s",
            generator,
            (
                " Keep the SC playbook anyway for its remediations of GuardDuty, Inspector, "
                "and Macie findings."
                if generator == "STANDARD_CONTROL"
                else ""
            ),
        )
    return None
