# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.config import Config
from EnableGuardDuty import lambda_handler as remediation
from moto import mock_aws

BOTO_CONFIG = Config(
    retries={"mode": "standard", "max_attempts": 10}, region_name="us-east-1"
)


# Test 1: Ensure existing GuardDuty detectors are enabled.
@mock_aws
def test_guardduty_enablement():
    guardduty = boto3.client("guardduty", config=BOTO_CONFIG)
    # Create GuardDuty detector in disabled state
    detector_id = guardduty.create_detector(Enable=False)["DetectorId"]

    # Check GuardDuty detector is disabled
    print(guardduty.get_detector(DetectorId=detector_id)["Status"])

    remediation(_={}, __="")

    # Assert GuardDuty detector is enabled after remediation is run
    assert guardduty.get_detector(DetectorId=detector_id)["Status"] == "ENABLED"


# Test 2: Ensure a GuardDuty detector is created and enabled.
@mock_aws
def test_create_detector():
    # Run remediation, without GuardDuty detector created
    remediation(_={}, __="")
    guardduty = boto3.client("guardduty", config=BOTO_CONFIG)

    detector_list = guardduty.list_detectors()["DetectorIds"]

    # Assert there is a GuardDuty detector after remediation is run
    assert detector_list != []

    # Assert that the GuardDuty detector is enabled
    for detector_id in detector_list:
        assert guardduty.get_detector(DetectorId=detector_id)["Status"] == "ENABLED"
