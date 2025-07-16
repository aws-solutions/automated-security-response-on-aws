# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
import pytest
from botocore.config import Config
from EnforceHTTPSForALB import Event, handler
from moto import mock_aws

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup_networking():
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)

    vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    vpc_id = vpc["VpcId"]

    subnet1 = ec2_client.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone="us-west-2a"
    )["Subnet"]

    subnet2 = ec2_client.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.2.0/24", AvailabilityZone="us-west-2b"
    )["Subnet"]

    security_group = ec2_client.create_security_group(
        GroupName="test-sg", Description="Test security group"
    )

    return {
        "vpc_id": vpc_id,
        "subnet1_id": subnet1["SubnetId"],
        "subnet2_id": subnet2["SubnetId"],
        "security_group_id": security_group["GroupId"],
    }


def create_target_group(vpc_id):
    elbv2_client = boto3.client("elbv2", config=BOTO_CONFIG)

    response = elbv2_client.create_target_group(
        Name="test-tg",
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        HealthCheckProtocol="HTTP",
        HealthCheckPort="80",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=30,
        HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=5,
        UnhealthyThresholdCount=2,
        TargetType="instance",
    )

    return response["TargetGroups"][0]["TargetGroupArn"]


@mock_aws
def test_handler_multiple_http_listeners():
    network_resources = setup_networking()
    elbv2_client = boto3.client("elbv2", config=BOTO_CONFIG)
    target_group_arn = create_target_group(network_resources["vpc_id"])

    alb = elbv2_client.create_load_balancer(
        Name="test-alb",
        Subnets=[network_resources["subnet1_id"], network_resources["subnet2_id"]],
        SecurityGroups=[network_resources["security_group_id"]],
    )
    alb_arn = alb["LoadBalancers"][0]["LoadBalancerArn"]

    # Create two HTTP listeners on different ports
    elbv2_client.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {
                "Type": "forward",
                "TargetGroupArn": target_group_arn,
            }
        ],
    )

    elbv2_client.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=8080,
        DefaultActions=[
            {
                "Type": "forward",
                "TargetGroupArn": target_group_arn,
            }
        ],
    )

    event = Event(ResourceARN=alb_arn)
    result = handler(event, None)

    assert result["Status"] == "success"

    listeners = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)["Listeners"]
    port_80_listener = next(
        (listener for listener in listeners if listener["Port"] == 80), None
    )
    port_8080_listener = next(
        (listener for listener in listeners if listener["Port"] == 8080), None
    )

    assert port_80_listener["DefaultActions"][0]["Type"] == "redirect"
    assert (
        port_80_listener["DefaultActions"][0]["RedirectConfig"]["Protocol"] == "HTTPS"
    )
    assert port_8080_listener["DefaultActions"][0]["Type"] == "redirect"
    assert (
        port_8080_listener["DefaultActions"][0]["RedirectConfig"]["Protocol"] == "HTTPS"
    )


@mock_aws
def test_handler_malformed_arn():
    event = Event(ResourceARN="invalid:arn:format")

    with pytest.raises(RuntimeError) as exc_info:
        handler(event, None)

    assert "Encountered error configuring HTTPS listener rule for ALB" in str(
        exc_info.value
    )


@mock_aws
def test_handler_no_listeners():
    network_resources = setup_networking()
    elbv2_client = boto3.client("elbv2", config=BOTO_CONFIG)

    alb = elbv2_client.create_load_balancer(
        Name="test-alb",
        Subnets=[network_resources["subnet1_id"], network_resources["subnet2_id"]],
        SecurityGroups=[network_resources["security_group_id"]],
    )
    alb_arn = alb["LoadBalancers"][0]["LoadBalancerArn"]

    event = Event(ResourceARN=alb_arn)
    result = handler(event, None)

    assert result["Status"] == "success"
    listeners = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)["Listeners"]
    new_listener = next(
        (listener for listener in listeners if listener["Protocol"] == "HTTP"),
        None,
    )

    assert new_listener is not None
    assert new_listener["DefaultActions"][0]["Type"] == "redirect"
    assert new_listener["DefaultActions"][0]["RedirectConfig"]["Protocol"] == "HTTPS"


@mock_aws
def test_handler_empty_listeners_list():
    network_resources = setup_networking()
    elbv2_client = boto3.client("elbv2", config=BOTO_CONFIG)

    alb = elbv2_client.create_load_balancer(
        Name="test-alb",
        Subnets=[network_resources["subnet1_id"], network_resources["subnet2_id"]],
        SecurityGroups=[network_resources["security_group_id"]],
    )
    alb_arn = alb["LoadBalancers"][0]["LoadBalancerArn"]

    event = Event(ResourceARN=alb_arn)
    result = handler(event, None)

    assert result["Status"] == "success"
    assert (
        f"Successfully configured HTTPS listener rule for ALB {alb_arn}"
        in result["Message"]
    )


@mock_aws
def test_handler_with_non_default_rule():
    network_resources = setup_networking()
    elbv2_client = boto3.client("elbv2", config=BOTO_CONFIG)
    target_group_arn = create_target_group(network_resources["vpc_id"])

    alb = elbv2_client.create_load_balancer(
        Name="test-alb",
        Subnets=[network_resources["subnet1_id"], network_resources["subnet2_id"]],
        SecurityGroups=[network_resources["security_group_id"]],
    )
    alb_arn = alb["LoadBalancers"][0]["LoadBalancerArn"]

    http_listener = elbv2_client.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {
                "Type": "forward",
                "TargetGroupArn": target_group_arn,
            }
        ],
    )

    elbv2_client.create_rule(
        ListenerArn=http_listener["Listeners"][0]["ListenerArn"],
        Priority=1,
        Conditions=[{"Field": "path-pattern", "Values": ["/test/*"]}],
        Actions=[
            {
                "Type": "forward",
                "TargetGroupArn": target_group_arn,
            }
        ],
    )

    event = Event(ResourceARN=alb_arn)
    result = handler(event, None)

    assert result["Status"] == "success"

    listeners = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)["Listeners"]
    http_listener = next(
        (listener for listener in listeners if listener["Port"] == 80), None
    )
    rules = elbv2_client.describe_rules(ListenerArn=http_listener["ListenerArn"])[
        "Rules"
    ]

    default_rule = next((r for r in rules if r["Priority"] == "default"), None)
    non_default_rule = next((r for r in rules if r["Priority"] == "1"), None)

    assert default_rule["Actions"][0]["Type"] == "redirect"
    assert non_default_rule["Actions"][0]["Type"] == "forward"


@mock_aws
def test_handler_multiple_http_listeners_various_ports():
    network_resources = setup_networking()
    elbv2_client = boto3.client("elbv2", config=BOTO_CONFIG)
    target_group_arn = create_target_group(network_resources["vpc_id"])

    alb = elbv2_client.create_load_balancer(
        Name="test-alb",
        Subnets=[network_resources["subnet1_id"], network_resources["subnet2_id"]],
        SecurityGroups=[network_resources["security_group_id"]],
    )
    alb_arn = alb["LoadBalancers"][0]["LoadBalancerArn"]

    # Create multiple HTTP listeners on different ports
    test_ports = [80, 8080, 8000, 3000]

    for port in test_ports:
        elbv2_client.create_listener(
            LoadBalancerArn=alb_arn,
            Protocol="HTTP",
            Port=port,
            DefaultActions=[
                {
                    "Type": "forward",
                    "TargetGroupArn": target_group_arn,
                }
            ],
        )

    event = Event(ResourceARN=alb_arn)
    result = handler(event, None)

    assert result["Status"] == "success"

    listeners = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)["Listeners"]

    for listener in listeners:
        assert listener["DefaultActions"][0]["Type"] == "redirect"
        assert listener["DefaultActions"][0]["RedirectConfig"]["Protocol"] == "HTTPS"
        assert listener["DefaultActions"][0]["RedirectConfig"]["Port"] == "443"


@mock_aws
def test_handler_mixed_http_https_listeners():
    network_resources = setup_networking()
    elbv2_client = boto3.client("elbv2", config=BOTO_CONFIG)
    target_group_arn = create_target_group(network_resources["vpc_id"])

    alb = elbv2_client.create_load_balancer(
        Name="test-alb",
        Subnets=[network_resources["subnet1_id"], network_resources["subnet2_id"]],
        SecurityGroups=[network_resources["security_group_id"]],
    )
    alb_arn = alb["LoadBalancers"][0]["LoadBalancerArn"]

    elbv2_client.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {
                "Type": "forward",
                "TargetGroupArn": target_group_arn,
            }
        ],
    )

    elbv2_client.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTPS",
        Port=443,
        DefaultActions=[
            {
                "Type": "forward",
                "TargetGroupArn": target_group_arn,
            }
        ],
    )

    event = Event(ResourceARN=alb_arn)
    result = handler(event, None)

    assert result["Status"] == "success"

    listeners = elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)["Listeners"]
    http_listener = next(
        (listener for listener in listeners if listener["Protocol"] == "HTTP"), None
    )
    https_listener = next(
        (listener for listener in listeners if listener["Protocol"] == "HTTPS"), None
    )

    assert http_listener["DefaultActions"][0]["Type"] == "redirect"
    assert http_listener["DefaultActions"][0]["RedirectConfig"]["Protocol"] == "HTTPS"

    # HTTPS listener should remain unchanged
    assert https_listener["DefaultActions"][0]["Type"] == "forward"
    assert https_listener["Protocol"] == "HTTPS"
