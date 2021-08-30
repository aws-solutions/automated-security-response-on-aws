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

ERROR_CREATING_BUCKET = 'Error creating bucket '

def connect_to_s3(boto_config):
    return boto3.client('s3', config=boto_config)

def create_logging_bucket(event, context):

    boto_config = Config(
        retries ={
            'mode': 'standard'
        }
    )
    s3 = connect_to_s3(boto_config)

    kms_key_arn = event['kms_key_arn']
    aws_account = event['account']
    aws_region = event['region']
    bucket_name = 'so0111-access-logs-' + aws_region + '-' + aws_account

    if create_bucket(s3, bucket_name, aws_region) == 'bucket_exists':
        return {"logging_bucket": bucket_name}
    encrypt_bucket(s3, bucket_name, kms_key_arn)
    put_access_block(s3, bucket_name)
    put_bucket_acl(s3, bucket_name)

    return {"logging_bucket": bucket_name}

def create_bucket(s3, bucket_name, aws_region):
    try:
        kwargs = {
            'Bucket': bucket_name,
            'ACL': 'private'
        }
        if aws_region != 'us-east-1':
            kwargs['CreateBucketConfiguration'] = {
                'LocationConstraint': aws_region
            }

        s3.create_bucket(**kwargs)

    except ClientError as ex:
        exception_type = ex.response['Error']['Code']
        # bucket already exists - return
        if exception_type in ["BucketAlreadyExists", "BucketAlreadyOwnedByYou"]:
            print('Bucket ' + bucket_name + ' already exists')
            return 'bucket_exists'
        else:
            print(ex)
            exit(ERROR_CREATING_BUCKET + bucket_name)
    except Exception as e:
        print(e)
        exit(ERROR_CREATING_BUCKET + bucket_name)

def encrypt_bucket(s3, bucket_name, kms_key_arn):
    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': kms_key_arn.split('key/')[1]
                        }
                    }
                ]
            }
        )
    except Exception as e:
        exit('Error encrypting bucket ' + bucket_name + ': ' + str(e))

def put_access_block(s3, bucket_name):
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
    except Exception as e:
        exit('Error setting public access block for bucket ' + bucket_name + ': ' + str(e))

def put_bucket_acl(s3, bucket_name):
    try:
        s3.put_bucket_acl(
            Bucket=bucket_name,
            GrantReadACP='uri=http://acs.amazonaws.com/groups/s3/LogDelivery',
            GrantWrite='uri=http://acs.amazonaws.com/groups/s3/LogDelivery'
        )
    except Exception as e:
        exit('Error setting ACL for bucket ' + bucket_name + ': ' + str(e))


