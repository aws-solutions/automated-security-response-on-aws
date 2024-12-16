# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import re
from typing import Any

import boto3
from botocore.exceptions import UnknownRegionError
from layer.awsapi_cached_client import AWSCachedClient
from layer.logger import Logger

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

LOG_LEVEL = os.getenv("log_level", "info")
LOGGER = Logger(loglevel=LOG_LEVEL)

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
    "standardsupported",
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
]


class StepFunctionLambdaAnswer:
    """
    Maintains a hash of AWS API Client connections by region and service
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
    standardsupported = ""
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

    def json(self):
        return self.__dict__

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
    default_account_alias = "Unknown"
    if not account_id:
        return default_account_alias
    try:
        aws = AWSCachedClient(AWS_REGION)
        organizations_client = aws.get_connection("organizations", AWS_REGION)
        accounts = []

        paginator = organizations_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            accounts.extend(page["Accounts"])
        return next(
            (account["Name"] for account in accounts if account["Id"] == account_id),
            default_account_alias,
        )
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
