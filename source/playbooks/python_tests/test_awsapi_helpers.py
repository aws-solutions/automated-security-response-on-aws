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
Simple test to validate that the request format coming from the Cfn template
will turn into a valid API call.
"""
from botocore.stub import Stubber, ANY
import pytest
from lib.awsapi_helpers import AWSClient, BotoSession

aws = AWSClient()

#------------------------------------------------------------------------------
# 
#------------------------------------------------------------------------------
def test_whoami():

    aws.connect('sts', 'us-east-1')
    stubber = Stubber(aws.CLIENT['sts']['us-east-1'])
    stubber.add_response(
        'get_caller_identity',
        {}
    )
    stubber.activate()
    myaccount = aws.whoami()
    assert 'sts' in aws.CLIENT
    assert 'us-east-1' in aws.CLIENT['sts']

#------------------------------------------------------------------------------
# 
#------------------------------------------------------------------------------
def test_postit_local():

    aws.connect('sns', 'us-east-1')
    aws.connect('sts', 'us-east-1')
    stubber1 = Stubber(aws.CLIENT['sts']['us-east-1'])
    stubber1.add_response(
        'get_caller_identity',
        {}
    )
    stubber1.activate()
    stubber2 = Stubber(aws.CLIENT['sns']['us-east-1'])
    stubber2.add_response(
        'publish',
        {},
        {
            'TopicArn': 'blarg',
            'Message': 'Test SNS message',
            'MessageStructure': 'json'
        }
    )
    stubber2.activate()
    aws.postit('test-topic', 'Test SNS message')

#------------------------------------------------------------------------------
# 
#------------------------------------------------------------------------------
def test_postit_remote():

    aws.connect('sns', 'eu-west-1')
    aws.connect('sts', 'us-east-1')
    stubber1 = Stubber(aws.CLIENT['sts']['us-east-1'])
    stubber1.add_response(
        'get_caller_identity',
        {}
    )
    stubber1.activate()
    stubber2 = Stubber(aws.CLIENT['sns']['eu-west-1'])
    stubber2.add_response(
        'publish',
        {},
        {
            'TopicArn': 'blarg',
            'Message': 'Test SNS message',
            'MessageStructure': 'json'
        }
    )
    stubber2.activate()
    aws.postit('test-topic', 'Test SNS message', region='eu-west-1')
