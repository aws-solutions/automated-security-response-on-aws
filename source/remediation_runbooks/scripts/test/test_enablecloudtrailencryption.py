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
import boto3
import botocore.session
from botocore.stub import Stubber
from botocore.config import Config
import pytest
from pytest_mock import mocker

import EnableCloudTrailEncryption as validate

my_session = boto3.session.Session()
my_region = my_session.region_name

#=====================================================================================
# EnableCloudTrailEncryption SUCCESS
#=====================================================================================
def test_EnableCloudTrailEncryption_success(mocker):
    event = {
        'SolutionId': 'SO0000',
        'SolutionVersion': '1.2.3',
        'trail': 'foobarbaz',
        'trail_region': my_region,
        'exec_region': my_region,
        'kms_key_arn': f'arn:aws:kms:{my_region}:111111111111:key'
    }

    BOTO_CONFIG = Config(
        retries ={
          'mode': 'standard'
        },
        region_name=my_region
    )

    ### LOGS
    ct_client = botocore.session.get_session().create_client('cloudtrail', config=BOTO_CONFIG)
    ct_stubber = Stubber(ct_client)

    ct_stubber.add_response(
        'update_trail',
        {},
        {
            'Name': event['trail'],
            'KmsKeyId': event['kms_key_arn']
        }
    )

    ct_stubber.activate()

    mocker.patch('EnableCloudTrailEncryption.connect_to_cloudtrail', return_value=ct_client)

    assert validate.enable_trail_encryption(event, {}) == {
        "response": {
            "message": f'Enabled KMS CMK encryption on {event["trail"]}',
            "status": "Success"
        }
    }
    
    ct_stubber.deactivate()
