#!/usr/bin/python
###############################################################################
#  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
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
Playbook Unit Test: CIS22.py
Run from /deployment/build/playbooks/CIS after running build-s3-dist.sh
"""
import json
import boto3
from botocore.stub import Stubber
import pytest
from pytest_mock import mocker
import cis22
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

def test_event_good(mocker):
    #--------------------------
    # Test data
    #
    event = utils.load_test_data(test_data + 'cis22.json', my_region)

    sns_message = {
        'Note': '"Enable CloudTrail log file validation" remediation was successful',
        'State': 'RESOLVED',
        'Account': '111111111111',
        'Remediation': 'Enable CloudTrail log file validation',
        'AffectedObject': 'CloudTrail: ExampleTrail',
        'metrics_data': {'status': 'RESOLVED'}
    }

    #--------------------------
    # Mock/stub
    #

    # Mock the constructor. We don't need the session created
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)
    mocker.patch('lib.awsapi_helpers.AWSClient.connect', return_value=None)

    # Mock the boto client and replace the BotoSession client with our stub
    awsc = boto3.client('cloudtrail')
    awsc_s = Stubber(awsc)
    awsc_s.add_response(
        'update_trail',
        {}
    )
    awsc_s.activate()
    mocker.patch('lib.awsapi_helpers.BotoSession.client', return_value=awsc)

    sns = mocker.patch('lib.awsapi_helpers.AWSClient.postit', return_value=None)

    # Mock Notifier
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')

    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    #--------------------------
    # Run the lambda
    #
    cis22.lambda_handler(event, None)

    init.assert_called_once_with(
        'INITIAL: "Enable CloudTrail log file validation" remediation started'
    )
    resolve.assert_called_once_with(
        'RESOLVED: "Enable CloudTrail log file validation" remediation was successful'
    )
    sns.assert_called_with('SO0111-SHARR_Topic', sns_message, my_region)
