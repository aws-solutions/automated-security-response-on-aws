#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.         #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                            #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################
import os
import pytest
from pytest_mock import mocker
import boto3
import botocore.session
from botocore.stub import Stubber, ANY
from botocore.exceptions import ClientError
import random
from createCustomAction import lambda_handler, CustomAction, CfnResponse, get_securityhub_client
from botocore.config import Config

os.environ['AWS_REGION'] = 'us-east-1'
os.environ['AWS_PARTITION'] = 'aws'
sechub = boto3.client('securityhub')

class MockContext(object):
    def __init__(self, name, version):
        self.function_name = name
        self.function_version = version
        self.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:123456789012:function:{name}:{version}".format(name=name, version=version))
        self.memory_limit_in_mb = float('inf')
        self.log_group_name = 'test-group'
        self.log_stream_name = 'test-stream'
        self.client_context = None

        self.aws_request_id = '-'.join([''.join([random.choice('0123456789abcdef') for _ in range(0, n)]) for n in [8, 4, 4, 4, 12]])

context = MockContext('SO0111-SHARR-Custom-Action-Lambda', 'v1.0.0')

def event(type):
    return {
        "ResourceProperties": {
            "Name": "Remediate with SHARR Test",
            "Description": "Test Submit the finding to AWS Security Hub Automated Response and Remediation",
            "Id": "SHARRRemediationTest"
        },
        "RequestType": type,
        "ResponseURL": "https://bogus"
    }

def test_get_client(mocker):
    client1 = get_securityhub_client()
    assert client1
    client2 = get_securityhub_client()
    assert client2 == client1

def test_lambda_handler(mocker):
    """
    Basic check for errors
    """
    mocker.patch('createCustomAction.CustomAction.create', return_value='12341234')
    lambda_handler(event('create'),{})
    
def test_create(mocker):
    """
    Test that the correct API call is executed
    """
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_response(
        'create_action_target',
        {
            'ActionTargetArn': 'foobarbaz'
        },
        {
            "Name": "Remediate with SHARR Test",
            "Description": " Test Submit the finding to AWS Security Hub Automated Response and Remediation",
            "Id": "SHARRRemediationTest"
        }
    )
    sechub_stub.activate()
    mocker.patch('createCustomAction.get_securityhub_client', return_value=sechub)
    mocker.patch('createCustomAction.CfnResponse.send', return_value=None)
    lambda_handler(event('create'), {})
    sechub_stub.deactivate()

def test_create_already_exists(mocker):
    """
    Test that there is no error when it already exists
    """
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error(
        'create_action_target',
        'ResourceConflictException'
    )
    sechub_stub.activate()
    mocker.patch('createCustomAction.get_securityhub_client', return_value=sechub)
    mocker.patch('createCustomAction.CfnResponse.send', return_value=None)
    customAction = CustomAction(
        '111122223333', 
        {
            "Name": "Remediate with SHARR Test",
            "Description": "Test Submit the finding to AWS Security Hub Automated Response and Remediation",
            "Id": "SHARRRemediationTest"
        }
    )
    assert customAction.create() == None
    sechub_stub.assert_no_pending_responses()
    sechub_stub.deactivate()

def test_create_no_sechub(mocker):
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error(
        'create_action_target',
        'InvalidAccessException'
    )
    sechub_stub.activate()
    mocker.patch('createCustomAction.get_securityhub_client', return_value=sechub)
    mocker.patch('createCustomAction.CfnResponse.send', return_value=None)
    customAction = CustomAction(
        '111122223333', 
        {
            "Name": "Remediate with SHARR Test",
            "Description": "Test Submit the finding to AWS Security Hub Automated Response and Remediation",
            "Id": "SHARRRemediationTest"
        }
    )
    assert customAction.create() == 'FAILED'
    sechub_stub.assert_no_pending_responses()
    sechub_stub.deactivate()

def test_create_other_client_error(mocker):
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error(
        'create_action_target',
        'ADoorIsAjar'
    )
    sechub_stub.activate()
    mocker.patch('createCustomAction.get_securityhub_client', return_value=sechub)
    mocker.patch('createCustomAction.CfnResponse.send', return_value=None)
    customAction = CustomAction(
        '111122223333', 
        {
            "Name": "Remediate with SHARR Test",
            "Description": "Test Submit the finding to AWS Security Hub Automated Response and Remediation",
            "Id": "SHARRRemediationTest"
        }
    )
    assert customAction.create() == 'FAILED'
    sechub_stub.assert_no_pending_responses()
    sechub_stub.deactivate()

def test_delete(mocker):
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_response(
        'delete_action_target',
        {
            'ActionTargetArn': 'foobarbaz'
        },
        {
            'ActionTargetArn': ANY
        }
    )
    sechub_stub.activate()
    mocker.patch('createCustomAction.get_securityhub_client', return_value=sechub)
    mocker.patch('createCustomAction.CfnResponse.send', return_value=None)
    customAction = CustomAction(
        '111122223333', 
        {
            "Name": "Remediate with SHARR Test",
            "Description": "Test Submit the finding to AWS Security Hub Automated Response and Remediation",
            "Id": "SHARRRemediationTest"
        }
    )
    assert customAction.delete() == 'SUCCESS'
    sechub_stub.assert_no_pending_responses()
    sechub_stub.deactivate()


def test_delete_already_exists(mocker):
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error(
        'delete_action_target',
        'ResourceNotFoundException'
    )
    sechub_stub.activate()
    mocker.patch('createCustomAction.get_securityhub_client', return_value=sechub)
    mocker.patch('createCustomAction.CfnResponse.send', return_value=None)
    customAction = CustomAction(
        '111122223333', 
        {
            "Name": "Remediate with SHARR Test",
            "Description": "Test Submit the finding to AWS Security Hub Automated Response and Remediation",
            "Id": "SHARRRemediationTest"
        }
    )
    assert customAction.delete() == 'SUCCESS'
    sechub_stub.deactivate()

def test_delete_no_sechub(mocker):
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error(
        'delete_action_target',
        'InvalidAccessException'
    )
    sechub_stub.activate()
    mocker.patch('createCustomAction.get_securityhub_client', return_value=sechub)
    mocker.patch('createCustomAction.CfnResponse.send', return_value=None)
    customAction = CustomAction(
        '111122223333', 
        {
            "Name": "Remediate with SHARR Test",
            "Description": "Test Submit the finding to AWS Security Hub Automated Response and Remediation",
            "Id": "SHARRRemediationTest"
        }
    )
    assert customAction.delete() == 'SUCCESS'
    sechub_stub.deactivate()

def test_delete_other_client_error(mocker):
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error(
        'delete_action_target',
        'ADoorIsAjar'
    )
    sechub_stub.activate()
    mocker.patch('createCustomAction.get_securityhub_client', return_value=sechub)
    mocker.patch('createCustomAction.CfnResponse.send', return_value=None)
    customAction = CustomAction(
        '111122223333', 
        {
            "Name": "Remediate with SHARR Test",
            "Description": "Test Submit the finding to AWS Security Hub Automated Response and Remediation",
            "Id": "SHARRRemediationTest"
        }
    )
    assert customAction.delete() == 'FAILED'
    sechub_stub.deactivate()

def test_customaction():
    test_object = CustomAction(
        '111122223333', 
        {
            'Name': 'foo',
            'Description': 'bar',
            'Id': 'baz'
        }
    )
    assert test_object.name == 'foo'
    assert test_object.description == 'bar'
    assert test_object.id == 'baz'
    assert test_object.account == '111122223333'

def test_cfn_response_success(mocker):
    mocker.patch('createCustomAction.CfnResponse.send', return_value=None)
    response_obj = CfnResponse(
        {
            'StackId': 'foobarbaz',
            'RequestId': 'thisisarequestid',
            'LogicalResourceId': 'SHARR-thingy',
            'ResponseURL': 'https://somewhere.over.the.rainbow'
        },
        context,
        'SUCCESS',
        {
            'foo':'bar'
        },
        'SHARRPhysResourceId'
    )
    good_body = '{"Status": "SUCCESS", "PhysicalResourceId": "SHARRPhysResourceId", "Reason": "See details in CloudWatch Log Stream: test-stream", "StackId": "foobarbaz", "RequestId": "thisisarequestid", "LogicalResourceId": "SHARR-thingy", "Data": {"foo": "bar"}}'
    assert response_obj.response_body == good_body
    assert response_obj.response_url == 'https://somewhere.over.the.rainbow'
    assert response_obj.response_headers == {'content-length': '247', 'content-type': ''}
