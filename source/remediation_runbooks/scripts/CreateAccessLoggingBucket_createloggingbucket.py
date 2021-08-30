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
from botocore.exceptions import ClientError
from botocore.config import Config

def connect_to_s3(boto_config):
    return boto3.client('s3', config=boto_config)

def create_logging_bucket(event, context):
    boto_config = Config(
        retries ={
          'mode': 'standard'
        }
    )
    s3 = connect_to_s3(boto_config)

    try:
        kwargs = {
            'Bucket': event['BucketName'],
            'GrantWrite': 'uri=http://acs.amazonaws.com/groups/s3/LogDelivery',
            'GrantReadACP': 'uri=http://acs.amazonaws.com/groups/s3/LogDelivery'
        }
        if event['AWS_REGION'] != 'us-east-1':
            kwargs['CreateBucketConfiguration'] = {
                'LocationConstraint': event['AWS_REGION']
            }

        s3.create_bucket(**kwargs)

        s3.put_bucket_encryption(
            Bucket=event['BucketName'],
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
        return {
            "output": {
                "Message": f'Bucket {event["BucketName"]} created'
            }
        }
    except ClientError as error:
        if error.response['Error']['Code'] != 'BucketAlreadyExists' and \
            error.response['Error']['Code'] != 'BucketAlreadyOwnedByYou':
            exit(str(error))
        else:
            return {
                "output": {
                    "Message": f'Bucket {event["BucketName"]} already exists'
                }
            }
    except Exception as e:
        print(e)
        exit(str(e))
