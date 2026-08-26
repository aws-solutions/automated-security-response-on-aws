# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re

import boto3
from botocore.config import Config
from EnableGuardDuty import lambda_handler as remediation
from moto import mock_aws

BOTO_CONFIG = Config(
    retries={"mode": "standard", "max_attempts": 10}, region_name="us-east-1"
)

# GuardDuty detector ARN format: arn:aws:guardduty:region:account-id:detector/detector-id
GUARDDUTY_DETECTOR_ARN_PATTERN = (
    r"^arn:(aws|aws-cn|aws-us-gov):guardduty:[a-z0-9-]+:\d{12}:detector/[a-f0-9]{32}$"
)


# Test 1: Ensure existing GuardDuty detectors are enabled.
@mock_aws
def test_guardduty_enablement():
    guardduty = boto3.client("guardduty", config=BOTO_CONFIG)
    # Create GuardDuty detector in disabled state
    detector_id = guardduty.create_detector(Enable=False)["DetectorId"]

    # Check GuardDuty detector is disabled
    print(guardduty.get_detector(DetectorId=detector_id)["Status"])

    result = remediation({"account_id": "111111111111"}, None)

    # Assert GuardDuty detector is enabled after remediation is run
    assert guardduty.get_detector(DetectorId=detector_id)["Status"] == "ENABLED"

    # Assert ARN is returned and matches expected format
    assert "ResourceArn" in result["output"]
    arn = result["output"]["ResourceArn"]
    assert re.match(GUARDDUTY_DETECTOR_ARN_PATTERN, arn), f"ARN format invalid: {arn}"
    assert f"detector/{detector_id}" in arn


# Test 2: Ensure a GuardDuty detector is created and enabled.
@mock_aws
def test_create_detector():
    # Run remediation, without GuardDuty detector created
    result = remediation({"account_id": "111111111111"}, None)
    guardduty = boto3.client("guardduty", config=BOTO_CONFIG)

    detector_list = guardduty.list_detectors()["DetectorIds"]

    # Assert there is a GuardDuty detector after remediation is run
    assert detector_list != []

    # Assert that the GuardDuty detector is enabled
    for detector_id in detector_list:
        assert guardduty.get_detector(DetectorId=detector_id)["Status"] == "ENABLED"

    # Assert ARN is returned and matches expected format
    assert "ResourceArn" in result["output"]
    arn = result["output"]["ResourceArn"]
    assert re.match(GUARDDUTY_DETECTOR_ARN_PATTERN, arn), f"ARN format invalid: {arn}"
    assert "detector/" in arn


# Test 3: Ensure ARN is returned when GuardDuty is already enabled.
@mock_aws
def test_already_enabled():
    guardduty = boto3.client("guardduty", config=BOTO_CONFIG)
    # Create GuardDuty detector in enabled state
    detector_id = guardduty.create_detector(Enable=True)["DetectorId"]

    result = remediation({"account_id": "111111111111"}, None)

    # Assert GuardDuty detector is still enabled
    assert guardduty.get_detector(DetectorId=detector_id)["Status"] == "ENABLED"

    # Assert ARN is returned and matches expected format
    assert "ResourceArn" in result["output"]
    arn = result["output"]["ResourceArn"]
    assert re.match(GUARDDUTY_DETECTOR_ARN_PATTERN, arn), f"ARN format invalid: {arn}"
    assert f"detector/{detector_id}" in arn
