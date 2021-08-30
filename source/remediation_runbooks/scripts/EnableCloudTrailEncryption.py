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

def connect_to_cloudtrail(region, boto_config):
    return boto3.client('cloudtrail', region_name=region, config=boto_config)

def enable_trail_encryption(event, context):
    """
    remediates CloudTrail.2 by enabling SSE-KMS
    On success returns a string map
    On failure returns NoneType
    """
    boto_config = Config(
        retries ={
          'mode': 'standard'
        }
    )
  
    if event['trail_region'] != event['exec_region']:
        exit('ERROR: cross-region remediation is not yet supported')

    ctrail_client = connect_to_cloudtrail(event['trail_region'], boto_config)
    kms_key_arn = event['kms_key_arn'] 

    try:
        ctrail_client.update_trail(
            Name=event['trail'],
            KmsKeyId=kms_key_arn
        )
        return {
            "response": {
                "message": f'Enabled KMS CMK encryption on {event["trail"]}',
                "status": "Success"
            }
        }
    except Exception as e:
        exit(f'Error enabling SSE-KMS encryption: {str(e)}')
