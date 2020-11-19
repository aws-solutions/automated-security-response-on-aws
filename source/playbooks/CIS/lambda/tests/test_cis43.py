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
import os
import boto3
from botocore.stub import Stubber
from pytest_mock import mocker
import cis43
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

AWS = AWSClient('aws','us-east-1')

def test_event_good(mocker):
    #--------------------------
    # Test data
    #
    event = utils.load_test_data(test_data + 'cis43.json', my_region)

    sns_message = {
        'Note': '"Remove all rules from the default security group" remediation was successful',
        'State': 'RESOLVED',
        'Account': '111111111111',
        'Remediation': 'Remove all rules from the default security group',
        'AffectedObject': 'Security Group: sg-02cfbecbc814a3c24',
        'metrics_data': {'status': 'RESOLVED'}
    }

    desc_sg = {
        "SecurityGroups": [
            {
                "Description": "Default SG",
                "GroupName": "SC-111111111111-pp-gz465ubujkfrs-SandboxSecurityGroup-175ZDF23V5MGX",
                "IpPermissions": [
                    {
                        "FromPort": 80,
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0"
                            }
                        ],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "ToPort": 80,
                        "UserIdGroupPairs": []
                    },
                    {
                        "FromPort": 9000,
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            {
                                "CidrIp": "72.21.198.65/32"
                            }
                        ],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "ToPort": 9000,
                        "UserIdGroupPairs": []
                    },
                    {
                        "FromPort": 22,
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0"
                            }
                        ],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "ToPort": 22,
                        "UserIdGroupPairs": []
                    }
                ],
                "OwnerId": "123412341234",
                "GroupId": "sg-006bf520b9581b2d9",
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0"
                            }
                        ],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": []
                    }
                ],
                "Tags": [
                ],
                "VpcId": "vpc-11111113"
            }
        ]
    }

    #--------------------------
    # Mock/stub
    #
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)
    mocker.patch('lib.awsapi_helpers.AWSClient.connect', return_value=None)

    # Mock the boto client and replace the BotoSession client with our stub
    awsc = boto3.resource('ec2')
    awsc_s = Stubber(awsc.meta.client)
    awsc_s.add_response(
        'describe_security_groups', desc_sg
    )
    awsc_s.add_response(
        'revoke_security_group_ingress',
        {}
    )
    awsc_s.add_response(
        'revoke_security_group_egress',
        {}
    )
    awsc_s.activate()
    mocker.patch('lib.awsapi_helpers.BotoSession.resource', return_value=awsc)

    sns = mocker.patch('lib.awsapi_helpers.AWSClient.postit', return_value=None)

    # Mock Notifier
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')

    # Prevent flushing to logs
    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    #--------------------------
    # Run the lambda
    #
    cis43.lambda_handler(event, None)
    init.assert_called_once_with(
        'INITIAL: "Remove all rules from the default security group" remediation started'
    )
    resolve.assert_called_once_with(
        'RESOLVED: "Remove all rules from the default security group" remediation was successful'
    )
    sns.assert_called_with('SO0111-SHARR_Topic', sns_message, my_region)
