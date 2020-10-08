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
Playbook Unit Test: CIS23.py
Run from /deployment/build/playbooks/CIS after running build-s3-dist.sh
"""
import json
import boto3
from botocore.stub import Stubber
from pytest_mock import mocker
import cis4142
from lib.logger import Logger
from lib.applogger import LogHandler
from lib.awsapi_helpers import BotoSession, AWSClient
import lib.sechub_findings
import tests.file_utilities as utils

log_level = 'info'
logger = Logger(loglevel=log_level)
test_data = 'tests/test_data/'

my_session = boto3.session.Session()
my_region = my_session.region_name

def test_event_good(mocker):
    #--------------------------
    # Test data
    #
    event = utils.load_test_data(test_data + 'cis4142.json', my_region)

    sns_message = {
        'Note': '"Block global access to port 22 and 3389" remediation was successfully invoked via AWS Systems Manager',
        'State': 'RESOLVED',
        'Account': '111111111111',
        'Remediation': 'Block global access to port 22 and 3389',
        'AffectedObject': 'Security Group: sg-02cfbecbc814a3c24',
        'metrics_data': {'status': 'RESOLVED'}
    }

    #--------------------------
    # Mock/stub
    #
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)
    mocker.patch('lib.awsapi_helpers.AWSClient.connect', return_value=None)

    # Mock the boto client and replace the BotoSession client with our stub
    awsc = boto3.client('ssm')
    awsc_s = Stubber(awsc)
    awsc_s.add_response(
        'start_automation_execution',
        {}
    )
    awsc_s.activate()
    mocker.patch('lib.awsapi_helpers.BotoSession.client', return_value=awsc)

    sns = mocker.patch('lib.awsapi_helpers.AWSClient.postit', return_value=None)

    # Mock Notifier
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')

    # Prevent flushing to logs
    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    #--------------------------
    # Run the lambda
    #
    cis4142.lambda_handler(event, None)
    init.assert_called_once_with(
        'INITIAL: "Block global access to port 22 and 3389" remediation started'
    )
    resolve.assert_called_once_with(
        'RESOLVED: "Block global access to port 22 and 3389" remediation was successfully invoked via AWS Systems Manager'
    )
    sns.assert_called_with('SO0111-SHARR_Topic', sns_message, my_region)
