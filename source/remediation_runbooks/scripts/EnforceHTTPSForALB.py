# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


def get_elbv2_client():
    return boto3.client("elbv2", config=boto_config)


class Event(TypedDict):
    ResourceARN: str


class Response(TypedDict):
    Message: str
    Status: str


def handler(event: Event, _) -> Response:
    """
    Remediates ELB.1 by adding a listener rule to route HTTP requests to HTTPS.
    """
    try:
        resource_arn = event["ResourceARN"]

        existing_http_listeners = get_existing_http_listener(resource_arn)

        if not existing_http_listeners:
            setup_http_to_https_listener_rule(resource_arn, "")

        for listener_arn in existing_http_listeners:
            setup_http_to_https_listener_rule(resource_arn, listener_arn)
        return {
            "Message": f"Successfully configured HTTPS listener rule for ALB {resource_arn}.",
            "Status": "success",
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error configuring HTTPS listener rule for ALB: {str(e)}"
        )


def get_existing_http_listener(load_balancer_arn: str) -> list[str]:
    try:
        elbv2_client = get_elbv2_client()
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)[
            "Listeners"
        ]
        result = []

        for listener in listeners:
            if listener["Protocol"] == "HTTP":
                result.append(listener["ListenerArn"])
        return result
    except Exception as e:
        raise RuntimeError(
            f"Failed to get existing port 80 rule for ALB {load_balancer_arn}: {str(e)}"
        )


def setup_http_to_https_listener_rule(
    load_balancer_arn: str, listener_arn: str
) -> None:
    try:
        elbv2_client = get_elbv2_client()
        if not listener_arn:
            elbv2_client.create_listener(
                LoadBalancerArn=load_balancer_arn,
                Protocol="HTTP",
                Port=80,
                DefaultActions=[
                    {
                        "Type": "redirect",
                        "RedirectConfig": {
                            "Protocol": "HTTPS",
                            "Port": "443",
                            "Host": "#{host}",
                            "Path": "/#{path}",
                            "Query": "#{query}",
                            "StatusCode": "HTTP_301",
                        },
                    },
                ],
            )
        else:
            elbv2_client.modify_listener(
                ListenerArn=listener_arn,
                DefaultActions=[
                    {
                        "Type": "redirect",
                        "RedirectConfig": {
                            "Protocol": "HTTPS",
                            "Port": "443",
                            "Host": "#{host}",
                            "Path": "/#{path}",
                            "Query": "#{query}",
                            "StatusCode": "HTTP_301",
                        },
                    }
                ],
            )
    except Exception as e:
        raise RuntimeError(
            f"Failed to setup HTTPS listener rule for ALB {load_balancer_arn}: {str(e)}"
        )
