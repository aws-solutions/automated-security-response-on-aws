# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import re
from typing import Any, NotRequired, TypedDict

import boto3
from botocore.exceptions import UnknownRegionError
from layer.awsapi_cached_client import AWSCachedClient
from layer.powertools_logger import get_logger

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

LOG_LEVEL = os.getenv("log_level", "info")
LOGGER = get_logger("utils", LOG_LEVEL)

properties = [
    "status",
    "message",
    "executionid",
    "affected_object",
    "remediation_status",
    "remediation_output",
    "logdata",
    "securitystandard",
    "securitystandardversion",
    "playbookenabled",
    "controlid",
    "accountid",
    "automationdocid",
    "remediationrole",
    "workflowdoc",
    "workflowaccount",
    "workflowrole",
    "eventtype",
    "resourceregion",
    "workflow_data",
    "executionaccount",
    "executionregion",
    "backup_s3_key",
]


class StepFunctionLambdaAnswerDict(TypedDict):
    """Typed shape of the dict returned by StepFunctionLambdaAnswer.json().

    Required fields are always set in __init__. NotRequired fields are
    populated conditionally by individual orchestrator Lambdas via update().
    """

    # Always set in __init__
    status: str
    message: str
    remediation_status: str
    logdata: list[Any]

    # Set conditionally via update() by specific Lambdas
    # resolve_ssm_doc_for_finding
    securitystandard: NotRequired[str]
    securitystandardversion: NotRequired[str]
    playbookenabled: NotRequired[str]
    controlid: NotRequired[str]
    accountid: NotRequired[str]
    automationdocid: NotRequired[str]
    remediationrole: NotRequired[str]
    resourceregion: NotRequired[str]

    # exec_ssm_doc
    executionid: NotRequired[str]
    executionaccount: NotRequired[str]
    executionregion: NotRequired[str]
    remediation_output: NotRequired[str]

    # check_ssm_execution
    affected_object: NotRequired[str]
    backup_s3_key: NotRequired[str]

    # get_approval_requirement
    workflowdoc: NotRequired[str]
    workflowaccount: NotRequired[str]
    workflowrole: NotRequired[str]
    workflow_data: NotRequired[dict[str, str]]
    eventtype: NotRequired[str]


class StepFunctionLambdaAnswer:
    """
    Structured response envelope for Orchestrator Step Function Lambda tasks.

    Each orchestrator Lambda creates an instance, populates fields via update(),
    and returns json() as the Lambda response. The Step Function reads specific
    fields from the response via resultSelector (e.g. $.Payload.status,
    $.Payload.automationdocid).

    update() only sets properties from the allowlist to prevent unexpected fields
    from leaking into the Step Function state.
    """

    status = "init"
    message = ""
    executionid = ""
    affected_object = ""
    remediation_status = ""
    remediation_output = ""
    logdata: Any = []
    securitystandard = ""
    securitystandardversion = ""
    playbookenabled = ""
    controlid = ""
    accountid = ""
    automationdocid = ""
    remediationrole = ""
    workflowdoc = ""
    workflowaccount = ""
    eventtype = ""
    resourceregion = ""
    workflow_data: dict[str, str] = (
        {}
    )  # Hash for workflow data so that it can be modified in
    # in the future without changing the source code

    def __init__(self):
        """Set message and status - minimum required fields"""
        self.status = ""
        self.message = ""
        self.remediation_status = ""
        self.logdata = []

    def __str__(self):
        return json.dumps(self.__dict__)

    def json(self) -> StepFunctionLambdaAnswerDict:
        # __dict__ returns dict[str, Any] which mypy can't reconcile with TypedDict.
        # The shape is guaranteed by the class attributes and update() allowlist.
        # A TypedDict can't be used as a base class for a mutable stateful object,
        # so this structural mismatch is inherent and unavoidable.
        return self.__dict__  # type: ignore[return-value]

    def update(self, answer_data):
        for property, value in answer_data.items():
            if property in properties:
                setattr(self, property, value)


def resource_from_arn(arn):
    """
    Strip off the leading parts of the ARN: arn:*:*:*:*:
    Return what's left. If no match, return the original predicate.
    """
    arn_pattern = re.compile(r"arn\:[\w,-]+:[\w,-]+:.*:\d*:(.*)")
    arn_match = arn_pattern.match(arn)
    answer = arn
    if arn_match:
        answer = arn_match.group(1)
    return answer


def partition_from_region(region_name):
    """
    returns the partition for a given region
    On success returns a string
    On failure returns aws
    """
    partition = ""
    session = boto3.Session()
    try:
        partition = session.get_partition_for_region(region_name)
    except UnknownRegionError:
        return "aws"

    return partition


def get_account_alias(account_id: str) -> str:
    if not account_id:
        return "Unknown"

    default_account_alias = account_id

    if os.getenv("DISABLE_ACCOUNT_ALIAS_LOOKUP", "false").lower() == "true":
        LOGGER.debug("Account alias lookup disabled via environment variable")
        return account_id

    try:
        aws = AWSCachedClient(AWS_REGION)
        organizations_client = aws.get_connection("organizations", AWS_REGION)
        response = organizations_client.describe_account(AccountId=account_id)
        return str(response["Account"]["Name"])
    except Exception as e:
        LOGGER.error(f"encountered error retrieving account alias: {str(e)}")
        return default_account_alias


def publish_to_sns(topic_name, message, region=""):
    """
    Post a message to an SNS topic
    """
    if not region:
        region = AWS_REGION
    partition = partition_from_region(region)
    AWS = AWSCachedClient(region)  # cached client object
    account = boto3.client("sts").get_caller_identity()["Account"]

    topic_arn = f"arn:{partition}:sns:{region}:{account}:{topic_name}"

    message_id = (
        AWS.get_connection("sns", region)
        .publish(TopicArn=topic_arn, Message=message)
        .get("MessageId", "error")
    )

    return message_id
