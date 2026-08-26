#!/usr/bin/env python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Tags AWS resources with the solution tag using the Resource Groups Tagging API.

This script is called by SSM documents after resource creation to apply
standardized tags to dynamically created AWS resources.
"""
from typing import Any, Dict, Optional, TypedDict

import boto3
from botocore.exceptions import ClientError

# Standard solution tag
SOLUTION_TAG_KEY = "Solutions:SolutionName"
SOLUTION_TAG_VALUE = "automated-security-response-on-aws"


class TagResourceEvent(TypedDict, total=False):
    """Input event for tag_resource function."""

    ResourceArn: str
    AdditionalTags: Dict[str, str]


class TagResourceResponse(TypedDict, total=False):
    """Response from tag_resource function."""

    success: bool
    resourceArn: Optional[str]
    failedResources: Dict[str, Dict[str, str]]
    error: str


def tag_resource(events: TagResourceEvent, _: Any) -> TagResourceResponse:
    """
    Tags an AWS resource with the solution tag using the Resource Groups Tagging API.

    Args:
        events: Dict containing:
            - ResourceArn: ARN of the resource to tag (required)
            - AdditionalTags: Optional dict of additional tags to apply
        context: Lambda context (unused)

    Returns:
        Dict containing:
            - success: Boolean indicating if tagging succeeded
            - resourceArn: The ARN that was tagged (if provided)
            - failedResources: Dict of any resources that failed to tag
            - error: Error message if an exception occurred (optional)
    """
    resource_arn: Optional[str] = events.get("ResourceArn")
    if not resource_arn:
        error_message = "ResourceArn is required but was not provided"
        print(f"Error: {error_message}")
        return TagResourceResponse(success=False, resourceArn=None, error=error_message)

    tags: Dict[str, str] = {SOLUTION_TAG_KEY: SOLUTION_TAG_VALUE}

    additional_tags: Dict[str, str] = events.get("AdditionalTags", {})
    tags.update(additional_tags)

    try:
        tagging_client = boto3.client("resourcegroupstaggingapi")

        response = tagging_client.tag_resources(
            ResourceARNList=[resource_arn], Tags=tags
        )

        failed_resources = response.get("FailedResourcesMap", {})

        if failed_resources:
            error_info: Dict[str, str] = failed_resources.get(resource_arn, {})
            error_message: str = error_info.get("ErrorMessage", "Unknown error")
            print(f"Failed to tag resource {resource_arn}: {error_message}")
            return TagResourceResponse(
                success=False,
                resourceArn=resource_arn,
                failedResources=failed_resources,
            )

        print(f"Successfully tagged resource {resource_arn}")
        return TagResourceResponse(
            success=True, resourceArn=resource_arn, failedResources={}
        )

    except ClientError as e:
        error_message = str(e)
        print(f"Error tagging resource {resource_arn}: {error_message}")
        return TagResourceResponse(
            success=False, resourceArn=resource_arn, error=error_message
        )
    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        print(f"Error tagging resource {resource_arn}: {error_message}")
        return TagResourceResponse(
            success=False, resourceArn=resource_arn, error=error_message
        )
