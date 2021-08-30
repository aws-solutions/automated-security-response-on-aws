#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################
import boto3
import json
import botocore.session
from botocore.stub import Stubber
from botocore.config import Config
import pytest
from pytest_mock import mocker

import EnableCloudTrailToCloudWatchLogging_waitforloggroup as validation

my_session = boto3.session.Session()
my_region = my_session.region_name

#=====================================================================================
# EnableCloudTrailToCloudWatchLogging_waitforloggroup
#=====================================================================================
def test_validation_success(mocker):
    event = {
        'SolutionId': 'SO0000',
        'SolutionVersion': '1.2.3',
        'LogGroup': 'my_loggroup',
        'region': my_region
    }
    notyet_response = {
        "logGroups": []
    }
    good_response = {
        "logGroups": [
            {
                "logGroupName": "my_loggroup",
                "creationTime": 1576239692739,
                "metricFilterCount": 0,
                "arn": "arn:aws:logs:us-east-1:111111111111:log-group:my_loggroup:*",
                "storedBytes": 109
            }
        ]
    }

    BOTO_CONFIG = Config(
        retries ={
          'mode': 'standard'
        },
        region_name=my_region
    )
    cwl_client = botocore.session.get_session().create_client('logs', config=BOTO_CONFIG)

    cwl_stubber = Stubber(cwl_client)

    cwl_stubber.add_response(
        'describe_log_groups',
        notyet_response
    )
    cwl_stubber.add_response(
        'describe_log_groups',
        notyet_response
    )
    cwl_stubber.add_response(
        'describe_log_groups',
        good_response
    )

    cwl_stubber.activate()
    mocker.patch('EnableCloudTrailToCloudWatchLogging_waitforloggroup.connect_to_logs', return_value=cwl_client)
    assert validation.wait_for_loggroup(event, {}) == "arn:aws:logs:us-east-1:111111111111:log-group:my_loggroup:*"
    
    cwl_stubber.deactivate()

def test_validation_failed(mocker):
    event = {
        'SolutionId': 'SO0000',
        'SolutionVersion': '1.2.3',
        'LogGroup': 'my_loggroup',
        'region': my_region
    }
    notyet_response = {
        "logGroups": []
    }
    good_response = {
        "logGroups": [
            {
                "logGroupName": "my_loggroup",
                "creationTime": 1576239692739,
                "metricFilterCount": 0,
                "arn": "arn:aws:logs:us-east-1:111111111111:log-group:my_loggroup:*",
                "storedBytes": 109
            }
        ]
    }

    BOTO_CONFIG = Config(
        retries ={
          'mode': 'standard'
        },
        region_name=my_region
    )
    cwl_client = botocore.session.get_session().create_client('logs', config=BOTO_CONFIG)

    cwl_stubber = Stubber(cwl_client)

    cwl_stubber.add_response(
        'describe_log_groups',
        notyet_response
    )
    cwl_stubber.add_response(
        'describe_log_groups',
        notyet_response
    )
    cwl_stubber.add_response(
        'describe_log_groups',
        notyet_response
    )

    cwl_stubber.activate()
    mocker.patch('EnableCloudTrailToCloudWatchLogging_waitforloggroup.connect_to_logs', return_value=cwl_client)
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = validation.wait_for_loggroup(event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'Failed to create Log Group my_loggroup: Timed out'
    cwl_stubber.deactivate()
