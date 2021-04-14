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
Playbook Unit Test: CIS23.py
Run from /deployment/build/playbooks/CIS after running build-s3-dist.sh
"""
import json
import os
os.environ['sendAnonymousMetrics'] = 'Yes'
import boto3
from botocore.stub import Stubber
from pytest_mock import mocker
import cis29
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

def test_not_configured(mocker):
    #--------------------------
    # Test data
    #
    event = utils.load_test_data(test_data + 'cis29.json', my_region)
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
    # Mock Notifier
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')
    update = mocker.patch('lib.sechub_findings.Finding.update_text')

    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    cis29.lambda_handler(event, None)

    resolve.assert_not_called()
    init.assert_not_called()

def test_event_good(mocker):
    #--------------------------
    # Test data
    #
    event = utils.load_test_data(test_data + 'cis29.json', my_region)

    sns_message = {
        'Note': '"Enable VPC flow logging in all VPCs" remediation was successful',
        'State': 'RESOLVED',
        'Account': '111111111111',
        'Remediation': 'Enable VPC flow logging in all VPCs',
        'AffectedObject': 'VPC Flow Logs for VPC: vpc-d1a07fba',
        'metrics_data': mocker.ANY
    }
    os.environ['AWS_SESSION_TOKEN'] = 'FAKETOKEN'
    os.environ['FLOW_LOG_ROLE_ARN'] = 'FAKELOGROLEARN'

    post_metrics_expected_parms = {
        'Solution': 'SO0111',
        'UUID': '12345678-1234-1234-1234-123412341234',
        'TimeStamp': mocker.ANY,
        'Data':
        {
            'generator_id': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/2.9',
            'type': '2.9 Ensure VPC flow logging is enabled in all VPCs',
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
    ssmc_s.activate()
    mocker.patch('lib.metrics.Metrics.connect_to_ssm', return_value=ssmc)
    post_metrics = mocker.patch('lib.metrics.Metrics.post_metrics_to_api', return_value=None)
    
    # Mock the constructor. We don't need the session created
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)
    mocker.patch('lib.awsapi_helpers.AWSClient.connect', return_value=None)

    awsc = [
        boto3.client('logs'),
        boto3.client('ec2')
    ]

    def mock_select(thing1, thing2):
        if thing2 == 'logs':
            return awsc[0]
        else:
            return awsc[1]

    # Mock the boto clients and replace the BotoSession client with our stub
    awsc_s = Stubber(awsc[0])
    awsc_s.add_response(
        'create_log_group',
        {}
    )
    awsc_s.activate()

    aws2c_s = Stubber(awsc[1])
    aws2c_s.add_response(
        'create_flow_logs',
        {}
    )
    aws2c_s.add_response(
        'describe_flow_logs',
        {
            'FlowLogs': [
                {
                    'FlowLogStatus': 'ACTIVE'
                }
            ]
        }
    )
    aws2c_s.activate()

    sns = mocker.patch('lib.awsapi_helpers.AWSClient.postit', return_value=None)

    # redirect to mock_select above to return the proper stub
    mocker.patch('lib.awsapi_helpers.BotoSession.client', new=mock_select)

    # Mock notifications
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')

    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    #--------------------------
    # Run the lambda
    #
    cis29.lambda_handler(event, None)
    init.assert_called_once_with(
        'INITIAL: "Enable VPC flow logging in all VPCs" remediation started'
    )
    resolve.assert_called_once_with(
        'RESOLVED: "Enable VPC flow logging in all VPCs" remediation was successful'
    )
    sns.assert_called_with('SO0111-SHARR_Topic', sns_message, my_region)
    post_metrics.assert_called_with(post_metrics_expected_parms)

def test_not_remediated(mocker):
    #--------------------------
    # Test data
    #
    event = utils.load_test_data(test_data + 'cis29.json', my_region)
    post_metrics_expected_parms = {
        'Solution': 'SO0111',
        'UUID': '12345678-1234-1234-1234-123412341234',
        'TimeStamp': mocker.ANY,
        'Data':
        {
            'generator_id': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/2.9',
            'type': '2.9 Ensure VPC flow logging is enabled in all VPCs',
            'productArn': mocker.ANY,
            'finding_triggered_by': 'Security Hub Findings - Custom Action',
            'region': mocker.ANY,
            'status': 'FAILED'
        },
        'Version': 'v1.2.0TEST'
    }
    os.environ['AWS_SESSION_TOKEN'] = 'FAKETOKEN'
    os.environ['FLOW_LOG_ROLE_ARN'] = 'FAKELOGROLEARN'

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
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)
    mocker.patch('lib.awsapi_helpers.AWSClient.connect', return_value=None)

    awsc = [
        boto3.client('logs'),
        boto3.client('ec2')
    ]

    def mock_select(thing1, thing2):
        if thing2 == 'logs':
            return awsc[0]
        else:
            return awsc[1]

    awsc_s = Stubber(awsc[0])
    awsc_s.add_response(
        'create_log_group',
        {}
    )
    awsc_s.activate()

    aws2c_s = Stubber(awsc[1])
    aws2c_s.add_response(
        'create_flow_logs',
        {}
    )
    aws2c_s.add_response(
        'describe_flow_logs',
        {
            'FlowLogs': [
            ]
        }
    )
    aws2c_s.activate()

    # redirect to mock_select above to return the proper stub
    mocker.patch('lib.awsapi_helpers.BotoSession.client', new=mock_select)

    # Mock notifications
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')
    update = mocker.patch('lib.sechub_findings.Finding.update_text')

    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    #--------------------------
    # Run the lambda
    #
    cis29.lambda_handler(event, None)

    init.assert_called_once_with(
        'INITIAL: "Enable VPC flow logging in all VPCs" remediation started'
    )
    update.assert_called_once_with(
        'FAILED: "Enable VPC flow logging in all VPCs" remediation failed. Please remediate manually',
        status='FAILED'
    )
    resolve.assert_not_called()
    post_metrics.assert_called_with(post_metrics_expected_parms)