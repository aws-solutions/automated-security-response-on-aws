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
import pytest
import deserializeApiList as script

def event():
    return {
        "SerializedList": "{\"blacklistedActionPattern\":\"s3:DeleteBucketPolicy,s3:PutBucketAcl,s3:PutBucketPolicy,s3:PutObjectAcl,s3:PutEncryptionConfiguration\"}"
    }

def expected():
    return "s3:DeleteBucketPolicy,s3:PutBucketAcl,s3:PutBucketPolicy,s3:PutObjectAcl,s3:PutEncryptionConfiguration"

def test_extract_list():
    assert script.runbook_handler(event(), {}) == expected()
