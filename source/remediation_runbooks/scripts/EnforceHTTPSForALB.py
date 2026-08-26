# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TYPE_CHECKING, TypedDict

import boto3
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_elbv2.client import ElasticLoadBalancingv2Client
else:
    ElasticLoadBalancingv2Client = object

boto_config = Config(retries={"mode": "standard"})


def get_elbv2_client() -> ElasticLoadBalancingv2Client:
    return boto3.client("elbv2", config=boto_config)


class Event(TypedDict):
    ResourceARN: str
    Region: str
    AccountId: str


class Response(TypedDict):
    Message: str
    Status: str


class Output(TypedDict):
    Response: Response
    ResourceArn: str


def handler(event: Event, _) -> Output:
    """
    Remediates ELB.1 by adding a listener rule to route HTTP requests to HTTPS.
    Returns the listener ARN that was created or modified.
    """
    try:
        resource_arn = event["ResourceARN"]

        existing_http_listeners = get_existing_http_listener(resource_arn)

        listener_arn = ""
        if not existing_http_listeners:
            listener_arn = setup_http_to_https_listener_rule(resource_arn, "")

        for existing_listener_arn in existing_http_listeners:
            listener_arn = setup_http_to_https_listener_rule(
                resource_arn, existing_listener_arn
            )

        return {
            "Response": {
                "Message": f"Successfully configured HTTPS listener rule for ALB {resource_arn}.",
                "Status": "success",
            },
            "ResourceArn": listener_arn,
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
    load_balancer_arn: str,
    listener_arn: str,
) -> str:
    try:
        elbv2_client = get_elbv2_client()
        if not listener_arn:
            response = elbv2_client.create_listener(
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
            if response.get("Listeners"):
                return response["Listeners"][0]["ListenerArn"]
            return ""
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
            return listener_arn
    except Exception as e:
        raise RuntimeError(
            f"Failed to setup HTTPS listener rule for ALB {load_balancer_arn}: {str(e)}"
        )
