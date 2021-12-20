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

import json
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

boto_config = Config(
    retries = {
            'mode': 'standard',
            'max_attempts': 10
        }
    )

def connect_to_s3():
    return boto3.client('s3', config=boto_config)

def policy_to_add(bucket):
    return {
        "Sid": "AllowSSLRequestsOnly",
        "Action": "s3:*",
        "Effect": "Deny",
        "Resource": [
            f'arn:aws:s3:::{bucket}',
            f'arn:aws:s3:::{bucket}/*'
        ],
        "Condition": {
            "Bool": {
                    "aws:SecureTransport": "false"
            }
        },
        "Principal": "*"
    }
def new_policy():
    return {
        "Id": "BucketPolicy",
        "Version": "2012-10-17",
        "Statement": []
    }

def add_ssl_bucket_policy(event, context):
    bucket_name = event['bucket']
    account_id = event['accountid']
    s3 = connect_to_s3()
    bucket_policy = {}
    try:
        existing_policy = s3.get_bucket_policy(
            Bucket=bucket_name,
            ExpectedBucketOwner=account_id
        )
        bucket_policy = json.loads(existing_policy['Policy'])
    except ClientError as ex:
        exception_type = ex.response['Error']['Code']
        # delivery channel already exists - return
        if exception_type not in ["NoSuchBucketPolicy"]:
            exit(f'ERROR: Boto3 s3 ClientError: {exception_type} - {str(ex)}')
    except Exception as e:
        exit(f'ERROR getting bucket policy for {bucket_name}: {str(e)}')

    if not bucket_policy:
        bucket_policy = new_policy()

    print(f'Existing policy: {bucket_policy}')
    bucket_policy['Statement'].append(policy_to_add(bucket_name))

    try:
        result = s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy, indent=4, default=str),
            ExpectedBucketOwner=account_id
        )
        print(result)
    except ClientError as ex:
        exception_type = ex.response['Error']['Code']
        exit(f'ERROR: Boto3 s3 ClientError: {exception_type} - {str(ex)}')
    except Exception as e:
        exit(f'ERROR putting bucket policy for {bucket_name}: {str(e)}')

    print(f'New policy: {bucket_policy}')
