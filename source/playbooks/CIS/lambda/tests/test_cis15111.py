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
"""
Playbook Unit Test: CIS15111.py
Run from /deployment/build/playbooks/CIS after running build-s3-dist.sh
"""
import os
os.environ['sendAnonymousMetrics'] = 'Yes'
import json
import boto3
from botocore.stub import Stubber
import pytest
from pytest_mock import mocker
import cis15111
from lib.logger import Logger
from lib.applogger import LogHandler
from lib.awsapi_helpers import BotoSession, AWSClient
from lib.applogger import LogHandler
import lib.sechub_findings
import tests.file_utilities as utils

log_level = 'INFO'
logger = Logger(loglevel=log_level)
test_data = 'tests/test_data/'

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

def test_single_event_good(mocker):
    # Read test data
    event = utils.load_test_data(test_data + 'CIS_1-6-single-select.json', my_region)

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
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.activate()
    mocker.patch('lib.metrics.Metrics.connect_to_ssm', return_value=ssmc)
    post_metrics = mocker.patch('lib.metrics.Metrics.post_metrics_to_api', return_value=None)

    # Mock the constructor. We don't need the session created
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)

    # create client directly through boto3 and stub it
    iamc = boto3.client('iam')
    iamc_s = Stubber(iamc)

    iamc_s.add_response(
        'update_account_password_policy',
        {}
    )
    iamc_s.activate()

    mocker.patch('lib.awsapi_helpers.BotoSession.client', return_value=iamc)
    mocker.patch('lib.awsapi_helpers.AWSClient.postit', return_value=None)

    # Mock Notifier
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')

    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    cis15111.lambda_handler(event, None)
    init.assert_called_once_with('INITIAL: "Set IAM Password Policy" remediation started')
    resolve.assert_called_once_with('RESOLVED: "Set IAM Password Policy" remediation was successful')

def test_multi_event_good(mocker):
    # Read test data
    event = utils.load_test_data(test_data + 'CIS_1-6-multi-select.json', my_region)

    sns_message = {
        'Note': '"Set IAM Password Policy" remediation was successful',
        'State': 'RESOLVED',
        'Account': '111111111111',
        'Remediation': 'Set IAM Password Policy',
        'AffectedObject': 'IAM Password Policy',
        'metrics_data': mocker.ANY
    }

    post_metrics_expected_parms = {
        'Solution': 'SO0111',
        'UUID': '12345678-1234-1234-1234-123412341234',
        'TimeStamp': mocker.ANY,
        'Data': {
            'generator_id': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.6',
            'type': '1.6 Ensure IAM password policy requires at least one lowercase letter',
            'productArn': mocker.ANY,
            'finding_triggered_by': 'Security Hub Findings - Custom Action',
            'region': mocker.ANY,
            'status': 'RESOLVED'
        },
        'Version': 'v1.2.0TEST'
    }

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
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.activate()
    mocker.patch('lib.metrics.Metrics.connect_to_ssm', return_value=ssmc)
    post_metrics = mocker.patch('lib.metrics.Metrics.post_metrics_to_api', return_value=None)

    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)

    # create client directly through boto3 and stub it
    iamc = boto3.client('iam')

    iamc_s = Stubber(iamc)

    # set up responses for the lambda. One for each call.
    # We expect 2 - one for each finding in this test data
    iamc_s.add_response(
        'update_account_password_policy',
        {}
    )
    iamc_s.add_response(
        'update_account_password_policy',
        {}
    )
    # Activate the stubber
    iamc_s.activate()

    # mock methods that we don't want to go through
    mocker.patch('lib.awsapi_helpers.BotoSession.client', return_value=iamc)

    # Mock Notifier's call to resolve so we can examine the parameters
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')
    sns = mocker.patch('lib.awsapi_helpers.AWSClient.postit')
    # Mock flush so it doesn't execute
    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    cis15111.lambda_handler(event, None)
    init.assert_called_with('INITIAL: "Set IAM Password Policy" remediation started')
    resolve.assert_called_with('RESOLVED: "Set IAM Password Policy" remediation was successful')
    sns.assert_called_with('SO0111-SHARR_Topic', sns_message, my_region)
    post_metrics.assert_called_with(post_metrics_expected_parms)
