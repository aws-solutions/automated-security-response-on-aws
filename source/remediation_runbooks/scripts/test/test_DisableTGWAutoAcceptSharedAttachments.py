# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `DisableTGWAutoAcceptSharedAttachments` remediation script"""

import boto3
from botocore.config import Config
from DisableTGWAutoAcceptSharedAttachments import lambda_handler
from moto import mock_aws


@mock_aws
def test_disable_tgw_autoaccept_shared_attachments():
    BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

    ec2 = boto3.client("ec2", config=BOTO_CONFIG)

    # Create new transit gateway with AutoAcceptSharedAttachments enabled
    tgw = ec2.create_transit_gateway(Options={"AutoAcceptSharedAttachments": "enable"})

    # Gather ID of the newly created transit gateway, store in event
    tgw_id = tgw["TransitGateway"]["TransitGatewayId"]
    event = {"TransitGatewayId": tgw_id}

    # Run remediation to disable AutoAcceptSharedAttachments given the transit gateway ID
    lambda_handler(event, {})

    # Check AutoAcceptSharedAttachments option after remediation is run
    tgw_updated = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])

    assert (
        tgw_updated["TransitGateways"][0]["Options"]["AutoAcceptSharedAttachments"]
        == "disable"
    )
