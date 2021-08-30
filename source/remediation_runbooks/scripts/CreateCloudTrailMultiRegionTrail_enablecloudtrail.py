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
from botocore.config import Config
from botocore.exceptions import ClientError

def connect_to_cloudtrail(boto_config):
    return boto3.client('cloudtrail', config=boto_config)

def enable_cloudtrail(event, context):

    boto_config = Config(
        retries ={
          'mode': 'standard'
        }
    )
    ct = connect_to_cloudtrail(boto_config)

    try:
        ct.create_trail(
            Name='multi-region-cloud-trail',
            S3BucketName=event['cloudtrail_bucket'],
            IncludeGlobalServiceEvents=True,
            EnableLogFileValidation=True,
            IsMultiRegionTrail=True,
            KmsKeyId=event['kms_key_arn']
        )
        ct.start_logging(
            Name='multi-region-cloud-trail'
        )
        return {
            "output": {
                "Message": f'CloudTrail Trail multi-region-cloud-trail created'
            }
        }
    except Exception as e:
        exit('Error enabling AWS Config: ' + str(e))
        