# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import List

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


def connect_to_guardduty():
    return boto3.client("guardduty", config=boto_config)


def lambda_handler(event, _):
    """
    Remediates untagged GuardDuty resources by tagging them with
    the required tag keys. If no required tag keys are
    specified, tags them with "SO0111-GuardDutyResource".
    """
    try:
        required_tags = get_required_tags_from_event(event)
        resource_arn = event["ResourceArn"]
        tag_guardduty_resource(tags=required_tags, resource_arn=resource_arn)
        return {
            "message": "Successfully tagged Guard Duty resource.",
            "status": "Success",
        }
    except Exception as e:
        raise RuntimeError(f"Failed to tag GuardDuty resource: {str(e)}")


def tag_guardduty_resource(tags: List[str], resource_arn: str):
    guardduty_client = connect_to_guardduty()
    tags_dict = {tag: "" for tag in tags}
    guardduty_client.tag_resource(ResourceArn=resource_arn, Tags=tags_dict)


def get_required_tags_from_event(event):
    required_tag_keys = event.get("RequiredTagKeys", {})
    if required_tag_keys:
        return [tag.strip() for tag in required_tag_keys]
    return None
