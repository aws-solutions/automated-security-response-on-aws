# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ec2():
    return boto3.client("ec2", config=boto_config)


def lambda_handler(event, _):
    tgw_id = event["TransitGatewayId"]

    ec2 = connect_to_ec2()

    try:
        ec2.modify_transit_gateway(
            TransitGatewayId=tgw_id, Options={"AutoAcceptSharedAttachments": "disable"}
        )

        tgw_updated = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])
        if (
            tgw_updated["TransitGateways"][0]["Options"]["AutoAcceptSharedAttachments"]
            == "disable"
        ):
            return {
                "response": {
                    "message": "Transit Gateway AutoAcceptSharedAttachments option disabled.",
                    "status": "Success",
                }
            }
        else:
            return {
                "response": {
                    "message": "Failed to disable AutoAcceptSharedAttachments on Transit Gateway.",
                    "status": "Failed",
                }
            }

    except Exception as e:
        exit("Failed to disable AutoAcceptSharedAttachments: " + str(e))
