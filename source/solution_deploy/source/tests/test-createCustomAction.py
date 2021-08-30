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

"""
Unit Test: check_ssm_doc_state.py
Run from /deployment/build/Orchestrator after running build-s3-dist.sh
"""


import pytest
import boto3
from botocore.stub import Stubber, ANY
from check_ssm_doc_state import get_lambda_role, lambda_handler
from awsapi_cached_client import AWSCachedClient

def test_get_lambda_role():
    assert get_lambda_role('basename', 'AFSBP', 'us-east-1') == 'basename-AFSBP_us-east-1'

def test_lambda_handler():
    """
    Verifies only that the APIs were called
    """
    AWS = AWSCachedClient('us-east-1')
    ssm_c = AWS.get_connection('ssm')
    sts_c = AWS.get_connection('sts')
    testing_account = sts_c.get_caller_identity().get('Account')
    stsc_stub = Stubber(sts_c)
    stsc_stub.add_response(
        'get_caller_identity',
        {}
    )
    stsc_stub.add_response(
        'assume_role',
        {
            # "RoleArn": "arn:aws:iam::" + testing_account + ":role/SO0111-SHARR-Orchestrator-Member_us-east-1"
        }
    )
    ssmc_stub = Stubber(ssm_c)
    ssmc_stub.add_response(
        'describe_document',
        {}
    )
    event = {
        "Finding": {
            "AwsAccountId": testing_account
        },
        "AutomationDocId": "test-doc-id"
    }
    # assert lambda_handler(event, {}) == '1234'
