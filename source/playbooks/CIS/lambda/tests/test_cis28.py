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
from pytest_mock import mocker
import cis28
from lib.logger import Logger
from lib.applogger import LogHandler
from lib.awsapi_helpers import BotoSession, AWSClient
from lib.applogger import LogHandler
import lib.sechub_findings

log_level = 'info'
logger = Logger(loglevel=log_level)
test_data = 'tests/test_data/'

def test_event_good(mocker):
    #--------------------------
    # Test data
    #
    test_event = open(test_data + 'cis28.json')
    event = json.loads(test_event.read())
    test_event.close()
    sns_message = {
        'Note': '"Enable rotation of customer-created CMKs" remediation was successful',
        'State': 'RESOLVED',
        'Account': '111111111111',
        'Remediation': 'Enable rotation of customer-created CMKs',
        'AffectedObject': 'Customer-Manager Key: 49efeff0-a251-4212-9bd0-0837123fa0c7b',
        'metrics_data': {'status': 'RESOLVED'}
    }

    #--------------------------
    # Mock/stub
    #
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)
    mocker.patch('lib.awsapi_helpers.AWSClient.connect', return_value=None)

    # Mock the boto client and replace the BotoSession client with our stub
    awsc = boto3.client('kms')
    awsc_s = Stubber(awsc)
    awsc_s.add_response(
        'enable_key_rotation',
        {}
    )
    awsc_s.add_response(
        'get_key_rotation_status',
        {
            'KeyRotationEnabled': True
        }
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
    cis28.lambda_handler(event, None)

    init.assert_called_once_with(
        'INITIAL: "Enable rotation of customer-created CMKs" remediation started'
    )
    resolve.assert_called_once_with(
        'RESOLVED: "Enable rotation of customer-created CMKs" remediation was successful'
    )
    sns.assert_called_with('SO0111-SHARR_Topic', sns_message, 'us-east-1')

def test_not_remediated(mocker):
    #--------------------------
    # Test data
    #
    test_event = open(test_data + 'cis28.json')
    event = json.loads(test_event.read())
    test_event.close()

    #--------------------------
    # Mock/stub
    #
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)
    mocker.patch('lib.awsapi_helpers.AWSClient.connect', return_value=None)

    # Mock the boto client and replace the BotoSession client with our stub
    awsc = boto3.client('kms')
    awsc_s = Stubber(awsc)
    awsc_s.add_response(
        'enable_key_rotation',
        {}
    )
    awsc_s.add_response(
        'get_key_rotation_status',
        {
            'KeyRotationEnabled': False
        }
    )
    awsc_s.activate()
    mocker.patch('lib.awsapi_helpers.BotoSession.client', return_value=awsc)

    sns = mocker.patch('lib.awsapi_helpers.AWSClient.postit', return_value=None)

    # Mock Notifier
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')
    update = mocker.patch('lib.sechub_findings.Finding.update_text')

    # Prevent flushing to logs
    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    #--------------------------
    # Run the lambda
    #
    cis28.lambda_handler(event, None)

    init.assert_called_once_with(
        'INITIAL: "Enable rotation of customer-created CMKs" remediation started'
    )
    update.assert_called_once_with(
        'FAILED: "Enable rotation of customer-created CMKs" remediation failed. Please remediate manually'
    )
    resolve.assert_not_called()
