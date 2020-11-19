#!/usr/bin/python
"""Utility functions for remediations"""
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

# *******************************************************************
# Required Modules:
# *******************************************************************

import json
import re

def remove_arn_prefix(arn):
    """
    Strip off the leading parts of the ARN: arn:*:*:*:*:
    Return what's left. If no match, return the original predicate.
    """
    arn_pattern = re.compile(r'arn\:[\w,-]+:[\w,-]+:.*:[0-9]*:(.*)')
    arn_match = arn_pattern.match(arn)
    answer = arn
    if arn_match:
        answer = arn_match.group(1)
    return answer

def test_remove_arn_prefix():

    testarn1 = "arn:aws-us-gov:iam:us-gov-west-1:222222222222:root"
    assert remove_arn_prefix(testarn1) == 'root'
    testarn2 = "arn:aws-cn:s3:::doc-example-bucket"
    assert remove_arn_prefix(testarn2) == 'doc-example-bucket'
    testarn3 = "This is a non-arn string"
    assert remove_arn_prefix(testarn3) == 'This is a non-arn string'

def partition_from_region(region_name):
    region_to_partition = {
        'us-gov-west-1': 'aws-us-gov',
        'us-gov-east-1': 'aws-us-gov',
        'cn-north-1': 'aws-cn',
        'cn-northwest-1': 'aws-cn',
        'default': 'aws'
    }
    if region_to_partition[region_name]:
        return region_to_partition[region_name]
    else:
        return region_to_partition['default']

def test_partition_from_region():

    assert partition_from_region('us-gov-west-1') == 'aws-us-gov'
    assert partition_from_region('cn-north-1') == 'aws-cn'
    # Note: does not validate region name. default expected
    assert partition_from_region('foo') == 'aws-cn'
    assert partition_from_region('eu-west-1') == 'aws-cn'
