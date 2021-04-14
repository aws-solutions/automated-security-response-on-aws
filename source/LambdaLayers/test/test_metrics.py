#!/usr/bin/python
###############################################################################
#  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

#
# Note: tests are executed in the build process from the assembled code in
# /deployment/temp
#
import os
import boto3
from botocore.stub import Stubber
import pytest
from pytest_mock import mocker
from metrics import Metrics
import file_utilities as utils

test_data = 'test/test_json_data/'
my_session = boto3.session.Session()
my_region = my_session.region_name

mock_ssm_get_parameter_uuid = {
    "Parameter": {
        "Name": "/Solutions/SO0111/anonymous_metrics_uuid",
        "Type": "String",
        "Value": "12345678-1234-1234-1234-123412341234",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": "arn:aws:ssm:us-east-1:1111111111111111:parameter/Solutions/SO0111/anonymous_metrics_uuid",
        "DataType": "text"
    }
}
mock_ssm_get_parameter_version = {
    "Parameter": {
        "Name": "/Solutions/SO0111/solution_version",
        "Type": "String",
        "Value": "v1.2.0TEST",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": "arn:aws:ssm:us-east-1:1111111111111111:parameter/Solutions/SO0111/anonymous_metrics_uuid",
        "DataType": "text"
    }
}

def test_metrics_construction(mocker):

    ssmc = boto3.client('ssm', region_name = my_region)
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.activate()

    mocker.patch('metrics.Metrics.connect_to_ssm', return_value=ssmc)

    metrics = Metrics({"sendAnonymousMetrics": "Yes"},{"detail-type": "unit-test"})

    assert metrics.solution_uuid == "12345678-1234-1234-1234-123412341234"
    assert metrics.solution_version == "v1.2.0TEST"

def test_get_metrics_from_finding(mocker):

    expected_response = {
        'generator_id': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3',
        'type': '1.3 Ensure credentials unused for 90 days or greater are disabled',
        'productArn': 'arn:aws:securityhub:' + my_region + '::product/aws/securityhub',
        'finding_triggered_by': 'unit-test',
        'region': mocker.ANY
    }

    finding = utils.load_test_data(test_data + 'CIS-1.3.json', my_region).get('detail').get('findings')[0]

    ssmc = boto3.client('ssm',region_name = my_region)
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.activate()

    mocker.patch('metrics.Metrics.connect_to_ssm', return_value=ssmc)

    metrics = Metrics({"sendAnonymousMetrics": "Yes"},{"detail-type": "unit-test"})

    assert metrics.get_metrics_from_finding(finding) == expected_response

def test_send_metrics(mocker):

    expected_response = {
        'Solution': 'SO0111',
        'UUID': '12345678-1234-1234-1234-123412341234',
        'TimeStamp': mocker.ANY,
        'Data': {
            'generator_id': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3',
            'type': '1.3 Ensure credentials unused for 90 days or greater are disabled',
            'productArn': mocker.ANY,
            'finding_triggered_by': 'unit-test',
            'region': mocker.ANY
        },
        'Version': 'v1.2.0TEST'
    }

    os.environ['sendAnonymousMetrics'] = 'Yes'

    finding = utils.load_test_data(test_data + 'CIS-1.3.json', my_region).get('detail').get('findings')[0]

    ssmc = boto3.client('ssm',region_name=my_region)
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.activate()

    mocker.patch('metrics.Metrics.connect_to_ssm', return_value=ssmc)

    metrics = Metrics({"sendAnonymousMetrics": "Yes"},{"detail-type": "unit-test"})
    metrics_data = metrics.get_metrics_from_finding(finding)

    send_metrics = mocker.patch('metrics.Metrics.post_metrics_to_api', return_value=None)

    metrics.send_metrics(metrics_data)

    send_metrics.assert_called_with(expected_response)
