# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Custom resource provider for AWS Security Hub Custom Action Target"""

# Test Event
# {
#     "ResourceProperties": {
#         "Name": "Remediate with ASR",
#         "Description": "Submit the finding to Automated Security Response on AWS",
#         "Id": "ASRRemediation"
#     },
#     "RequestType": "Create",
#     "ResponseURL": "https://bogus"
# }

import json
import os

import boto3
import cfnresponse
from botocore.config import Config
from botocore.exceptions import ClientError
from layer.logger import Logger

# initialize logger
LOG_LEVEL = os.getenv("log_level", "info")
logger_obj = Logger(loglevel=LOG_LEVEL)
REGION = os.getenv("AWS_REGION", "us-east-1")
PARTITION = os.getenv("AWS_PARTITION", default="aws")  # Set by deployment template

BOTO_CONFIG = Config(retries={"mode": "standard"})
CLIENTS = {}


def get_securityhub_client():
    if "securityhub" not in CLIENTS:
        CLIENTS["securityhub"] = boto3.client("securityhub", config=BOTO_CONFIG)
    return CLIENTS["securityhub"]


class InvalidCustomAction(Exception):
    pass


class CustomAction(object):
    """
    Security Hub CustomAction class
    """

    name = ""
    description = ""
    id = ""
    account = ""

    def __init__(self, account, properties):
        self.name = properties.get("Name", "")
        self.description = properties.get("Description", "")
        self.id = properties.get("Id", "")
        self.account = account
        if not self.name or not self.description or not self.id:
            raise InvalidCustomAction

    def create(self):
        client = get_securityhub_client()
        try:
            return client.create_action_target(
                Name=self.name, Description=self.description, Id=self.id
            )["ActionTargetArn"]
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceConflictException":
                logger_obj.info("ResourceConflictException: already exists. Continuing")
                return
            elif error.response["Error"]["Code"] == "InvalidAccessException":
                logger_obj.info(
                    "InvalidAccessException - Account is not subscribed to AWS Security Hub."
                )
                return "FAILED"
            else:
                logger_obj.error(error)
                return "FAILED"
        except Exception:
            return "FAILED"

    def delete(self):
        client = get_securityhub_client()
        try:
            target_arn = f"arn:{PARTITION}:securityhub:{REGION}:{self.account}:action/custom/{self.id}"
            logger_obj.info(target_arn)
            client.delete_action_target(ActionTargetArn=target_arn)
            return "SUCCESS"
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                logger_obj.info("ResourceNotFoundException - nothing to delete.")
                return "SUCCESS"
            elif error.response["Error"]["Code"] == "InvalidAccessException":
                logger_obj.info(
                    "InvalidAccessException - not subscribed to Security Hub (nothing to delete)."
                )
                return "SUCCESS"
            else:
                logger_obj.error(error)
                return "FAILED"
        except Exception as e:
            logger_obj.error(e)
            return "FAILED"


def get_account_id():
    return boto3.client("sts").get_caller_identity()["Account"]


def lambda_handler(event, context):
    response_data = {}
    physical_resource_id = ""
    err_msg = ""

    properties = event.get("ResourceProperties", {})
    logger_obj.info(json.dumps(properties))
    account_id = get_account_id()
    custom_action = CustomAction(account_id, properties)
    physical_resource_id = "CustomAction" + properties.get("Id", "ERROR")

    try:
        status = "ERROR"
        if (
            event["RequestType"].upper() == "CREATE"
            or event["RequestType"].upper() == "UPDATE"
        ):
            logger_obj.info(event["RequestType"].upper() + ": " + physical_resource_id)
            custom_action_result = custom_action.create()
            if custom_action_result == "FAILED":
                status = "FAILED"
            else:
                response_data["Arn"] = custom_action_result
                status = "SUCCESS"

        elif event["RequestType"].upper() == "DELETE":
            logger_obj.info("DELETE: " + physical_resource_id)
            status = custom_action.delete()

        else:
            err_msg = "Invalid RequestType: " + event["RequestType"]
            logger_obj.error(err_msg)

        cfnresponse.send(
            event, context, status, response_data, physical_resource_id, reason=err_msg
        )
        return

    except Exception as err:
        logger_obj.error("An exception occurred: ")
        err_msg = err.__class__.__name__ + ": " + str(err)
        logger_obj.error(err_msg)
