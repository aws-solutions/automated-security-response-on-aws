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

import json
import re

def resource_from_arn(arn):
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

def partition_from_region(region_name):
    """
    returns the partition for a given region
    Note: this should be a Boto3 function and should be deprecated once it is.
    On success returns a string
    On failure returns NoneType
    """

    parts = region_name.split('-')
 
    try:
        if parts[0] == 'us':
            return 'aws-us-gov'
        elif parts[0] == 'cn':
            return 'aws-cn'
        else:
            return 'aws'
    except:
        return
