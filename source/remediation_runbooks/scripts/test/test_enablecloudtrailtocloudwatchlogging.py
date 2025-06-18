# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Dict, List

import boto3
import botocore.session
import EnableCloudTrailToCloudWatchLogging_waitforloggroup as validation
import pytest
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name


@pytest.fixture(autouse=True)
def patch_sleep_between_attempts(mocker):
    mocker.patch(
        "EnableCloudTrailToCloudWatchLogging_waitforloggroup.sleep_between_attempts"
    )


# =====================================================================================
# EnableCloudTrailToCloudWatchLogging_waitforloggroup
# =====================================================================================
def test_validation_success(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "LogGroup": "my_loggroup",
        "region": my_region,
    }
    notyet_response: Dict[str, List[str]] = {"logGroups": []}
    good_response = {
        "logGroups": [
            {
                "logGroupName": "my_loggroup",
                "creationTime": 1576239692739,
                "metricFilterCount": 0,
                "arn": "arn:aws:logs:us-east-1:111111111111:log-group:my_loggroup:*",
                "storedBytes": 109,
            }
        ]
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    cwl_client = botocore.session.get_session().create_client(
        "logs", config=BOTO_CONFIG
    )

    cwl_stubber = Stubber(cwl_client)

    cwl_stubber.add_response("describe_log_groups", notyet_response)
    cwl_stubber.add_response("describe_log_groups", notyet_response)
    cwl_stubber.add_response("describe_log_groups", good_response)

    cwl_stubber.activate()
    mocker.patch(
        "EnableCloudTrailToCloudWatchLogging_waitforloggroup.connect_to_logs",
        return_value=cwl_client,
    )

    assert (
        validation.wait_for_loggroup(event, {})
        == "arn:aws:logs:us-east-1:111111111111:log-group:my_loggroup:*"
    )

    cwl_stubber.deactivate()


def test_validation_failed(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "LogGroup": "my_loggroup",
        "region": my_region,
    }
    notyet_response: Dict[str, List[str]] = {"logGroups": []}

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    cwl_client = botocore.session.get_session().create_client(
        "logs", config=BOTO_CONFIG
    )

    cwl_stubber = Stubber(cwl_client)

    cwl_stubber.add_response("describe_log_groups", notyet_response)
    cwl_stubber.add_response("describe_log_groups", notyet_response)
    cwl_stubber.add_response("describe_log_groups", notyet_response)

    cwl_stubber.activate()
    mocker.patch(
        "EnableCloudTrailToCloudWatchLogging_waitforloggroup.connect_to_logs",
        return_value=cwl_client,
    )

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        validation.wait_for_loggroup(event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "Failed to create Log Group my_loggroup: Timed out"
    )
    cwl_stubber.deactivate()
