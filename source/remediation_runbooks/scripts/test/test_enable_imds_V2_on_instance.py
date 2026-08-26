# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `enable_imds_v2_on_instance` remediation script"""
from __future__ import annotations

from unittest.mock import patch

import boto3
import pytest
from botocore.config import Config
from enable_imds_v2_on_instance import lambda_handler
from moto import mock_aws
from moto.ec2.models.instances import MetadataOptions

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
REGION = "us-east-1"

_original_metadata_init = MetadataOptions.__init__


def _patched_metadata_init(self: MetadataOptions, options: dict) -> None:
    """Workaround for moto bug where HttpPutResponseHopLimit is None when not provided.
    Per AWS docs, HttpPutResponseHopLimit is not required and will keep the existing setting if not set - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceMetadataOptions.html
    """
    if options.get("HttpPutResponseHopLimit") is None:
        options["HttpPutResponseHopLimit"] = 1
    _original_metadata_init(self, options)


@mock_aws
@patch.object(MetadataOptions, "__init__", _patched_metadata_init)
def test_enables_imdsv2_on_instance():
    # Arrange
    ec2 = boto3.client("ec2", config=BOTO_CONFIG, region_name=REGION)
    instance = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
    )
    instance_id = instance["Instances"][0]["InstanceId"]
    instance_arn = f"arn:aws:ec2:{REGION}:111111111111:instance/{instance_id}"

    # Act
    response = lambda_handler({"instance_arn": instance_arn}, {})

    # Assert
    assert response["InstanceId"] == instance_id
    assert response["HttpTokens"] == "required"
    assert response["HttpEndpoint"] == "enabled"

    described = ec2.describe_instances(InstanceIds=[instance_id])
    metadata_options = described["Reservations"][0]["Instances"][0]["MetadataOptions"]
    assert metadata_options["HttpTokens"] == "required"
    assert metadata_options["HttpEndpoint"] == "enabled"


@mock_aws
def test_raises_on_invalid_instance_id():
    # Arrange
    event = {
        "instance_arn": "arn:aws:ec2:us-east-1:111111111111:instance/i-doesnotexist"
    }

    # Act / Assert
    with pytest.raises(RuntimeError, match="There was an error enabling IMDSv2"):
        lambda_handler(event, {})
