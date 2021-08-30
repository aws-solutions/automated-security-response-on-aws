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

#
# Note: tests are executed in the build process from the assembled code in
# /deployment/temp
#
from botocore.stub import Stubber, ANY
import pytest
from awsapi_cached_client import AWSCachedClient

AWS = AWSCachedClient('us-east-1')

def test_create_client():

    AWS.get_connection('sns') # in us-east-1
    my_account = AWS.account
    assert my_account
    assert 'sns' in AWS.client
    assert 'us-east-1' in AWS.client['sns']
    AWS.get_connection('ec2')
    assert 'ec2' in AWS.client
    assert 'us-east-1' in AWS.client['ec2']
    AWS.get_connection('iam','ap-northeast-1')
    assert 'iam' in AWS.client
    assert 'ap-northeast-1' in AWS.client['iam']
