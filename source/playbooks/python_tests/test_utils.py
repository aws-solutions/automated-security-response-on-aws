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

#
# Note: tests are executed in the build process from the assembled code in
# /deployment/temp
#

from lib.aws_utils import resource_from_arn, partition_from_region

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
