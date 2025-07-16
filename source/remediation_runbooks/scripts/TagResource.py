# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import List, TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


class Event(TypedDict):
    ResourceArn: str
    ResourceType: str
    RequiredTagKeys: List[str]


def get_guardduty_client():
    return boto3.client("guardduty", config=boto_config)


def get_dynamodb_client():
    return boto3.client("dynamodb", config=boto_config)


def lambda_handler(event, _):
    """
    Remediates untagged resources by tagging them with
    the required tag keys. If no required tag keys are
    specified, tags them with a default key, e.g. "SO0111-ASR-GuardDutyResource".
    """
    try:
        required_tags = get_required_tags_from_event(event)
        resource_arn = event["ResourceArn"]
        resource_type = event["ResourceType"]

        if resource_type == "GuardDuty":
            tag_guardduty_resource(tags=required_tags, resource_arn=resource_arn)
        elif resource_type == "DynamoDBTable":
            tag_dynamodb_table_resource(tags=required_tags, resource_arn=resource_arn)
        return {
            "message": f"Successfully tagged resource {resource_arn}.",
            "status": "Success",
        }
    except Exception as e:
        raise RuntimeError(f"Failed to tag resource: {str(e)}")


def tag_guardduty_resource(tags: List[str], resource_arn: str):
    guardduty_client = get_guardduty_client()
    tags_dict = {tag: "" for tag in tags}
    guardduty_client.tag_resource(ResourceArn=resource_arn, Tags=tags_dict)


def tag_dynamodb_table_resource(tags: List[str], resource_arn: str):
    dynamodb_client = get_dynamodb_client()
    tags_list = [{"Key": tag, "Value": ""} for tag in tags]
    dynamodb_client.tag_resource(ResourceArn=resource_arn, Tags=tags_list)


def get_required_tags_from_event(event):
    required_tag_keys = event.get("RequiredTagKeys", {})
    if required_tag_keys:
        return [tag.strip() for tag in required_tag_keys]
    return None
