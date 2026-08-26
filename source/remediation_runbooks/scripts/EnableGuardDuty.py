# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from typing import TYPE_CHECKING, TypedDict

import boto3
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_guardduty.client import GuardDutyClient
else:
    GuardDutyClient = object

BOTO_CONFIG = Config(retries={"mode": "standard"})


class Event(TypedDict, total=False):
    account_id: str


class Output(TypedDict):
    Message: str
    ResourceArn: str


def get_partition_from_region(region: str) -> str:
    """Derive AWS partition from region name."""
    if region.startswith("cn-"):
        return "aws-cn"
    elif region.startswith("us-gov"):
        return "aws-us-gov"
    else:
        return "aws"


def connect_to_guardduty(boto_config: Config) -> GuardDutyClient:
    return boto3.client("guardduty", config=boto_config)


def lambda_handler(event: Event, _) -> Output:
    guardduty = connect_to_guardduty(BOTO_CONFIG)
    region = os.environ.get("AWS_REGION", "us-east-1")
    partition = get_partition_from_region(region)
    account_id = event.get("account_id", "")

    detector_list = guardduty.list_detectors()["DetectorIds"]

    if detector_list == []:
        detector = guardduty.create_detector(
            Enable=True,
            DataSources={
                "S3Logs": {"Enable": True},
                "Kubernetes": {"AuditLogs": {"Enable": True}},
            },
        )
        detector_id = detector["DetectorId"]
        resource_arn = (
            f"arn:{partition}:guardduty:{region}:{account_id}:detector/{detector_id}"
        )

        return {
            "output": {
                "Message": f"GuardDuty Enabled. Detector {detector_id} created",
                "ResourceArn": resource_arn,
            }
        }

    else:
        for detector_id in detector_list:
            if guardduty.get_detector(DetectorId=detector_id)["Status"] == "DISABLED":
                guardduty.update_detector(
                    DetectorId=detector_id,
                    Enable=True,
                    DataSources={
                        "S3Logs": {"Enable": True},
                        "Kubernetes": {"AuditLogs": {"Enable": True}},
                    },
                )
                resource_arn = f"arn:{partition}:guardduty:{region}:{account_id}:detector/{detector_id}"
                return {
                    "output": {
                        "Message": f"GuardDuty Enabled. Existing detector {detector_id} has been enabled.",
                        "ResourceArn": resource_arn,
                    }
                }

        # GuardDuty is already enabled, return ARN of first detector
        detector_id = detector_list[0]
        resource_arn = (
            f"arn:{partition}:guardduty:{region}:{account_id}:detector/{detector_id}"
        )
        return {
            "output": {
                "Message": "GuardDuty is already enabled.",
                "ResourceArn": resource_arn,
            }
        }
