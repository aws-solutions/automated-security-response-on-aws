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

import pytest
from utils import resource_from_arn, partition_from_region, publish_to_sns

def test_notification():
    return {
        'INFO': 'A door is ajar',
        'finding': {
            'finding_id': '8f400859-26b0-4cd4-a935-1f96c82343e9',
            'finding_description': 'Description of the finding',
            'standard_name': 'Long Standard Name',
            'standard_version': 'v1.0.0',
            'standard_control': 'Control.Id',
            'title': 'CloudTrail.1 CloudTrail should be enabled and configured with at least one multi-region trail',
            'region': 'ap-northwest-1',
            'account': '111122223333',
            'finding_arn':   "arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/CloudTrail.1/finding/8f400859-26b0-4cd4-a935-1f96c82343e9"
        }
    }

def test_resource_from_arn():

    testarn1 = "arn:aws-us-gov:iam:us-gov-west-1:222222222222:root"
    assert resource_from_arn(testarn1) == 'root'
    testarn2 = "arn:aws-cn:s3:::doc-example-bucket"
    assert resource_from_arn(testarn2) == 'doc-example-bucket'
    testarn3 = "This is a non-arn string"
    assert resource_from_arn(testarn3) == 'This is a non-arn string'

def test_partition_from_region():

    assert partition_from_region('us-gov-west-1') == 'aws-us-gov'
    assert partition_from_region('cn-north-1') == 'aws-cn'
    # Note: does not validate region name. default expected
    assert partition_from_region('foo') == 'aws'
    assert partition_from_region('eu-west-1') == 'aws'
