# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard"})


def connect_to_guardduty(boto_config):
    return boto3.client("guardduty", config=boto_config)


def lambda_handler(_, __):
    guardduty = connect_to_guardduty(BOTO_CONFIG)

    detector_list = guardduty.list_detectors()["DetectorIds"]

    if detector_list == []:
        detector = guardduty.create_detector(
            Enable=True,
            DataSources={
                "S3Logs": {"Enable": True},
                "Kubernetes": {"AuditLogs": {"Enable": True}},
            },
        )

        return {
            "output": {
                "Message": f'GuardDuty Enabled. Detector {detector["DetectorId"]} created'
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
                return {
                    "output": {
                        "Message": f"GuardDuty Enabled. Existing detector {detector_id} has been enabled."
                    }
                }

        return {"output": {"Message": "GuardDuty is already enabled."}}
