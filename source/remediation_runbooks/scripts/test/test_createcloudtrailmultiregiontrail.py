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
import json
import botocore.session
from botocore.stub import Stubber
from botocore.config import Config
import pytest
from pytest_mock import mocker

import CreateCloudTrailMultiRegionTrail_createcloudtrailbucket as createcloudtrailbucket
import CreateCloudTrailMultiRegionTrail_createcloudtrailbucketpolicy as createcloudtrailbucketpolicy
import CreateCloudTrailMultiRegionTrail_createloggingbucket as createloggingbucket
import CreateCloudTrailMultiRegionTrail_enablecloudtrail as enablecloudtrail
import CreateCloudTrailMultiRegionTrail_process_results as process_results

my_session = boto3.session.Session()
my_region = my_session.region_name

#=====================================================================================
# CreateCloudTrailMultiRegionTrail_createcloudtrailbucket
#=====================================================================================
def test_create_encrypted_bucket(mocker):
    event = {
        'SolutionId': 'SO0000',
        'SolutionVersion': '1.2.3',
        'region': my_region,
        'kms_key_arn': 'arn:aws:kms:us-east-1:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab',
        'account': '111111111111',
        'logging_bucket': 'mah-loggin-bukkit'
    }
    BOTO_CONFIG = Config(
        retries ={
          'mode': 'standard'
        },
        region_name=my_region
    )
    s3 = botocore.session.get_session().create_client('s3', config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)
    kwargs = {
        'Bucket': 'so0111-aws-cloudtrail-111111111111',
        'ACL': 'private'
    }
    if my_region != 'us-east-1':
        kwargs['CreateBucketConfiguration'] = {
            'LocationConstraint': my_region
        }

    s3_stubber.add_response(
        'create_bucket',
        {},
        kwargs
    )

    s3_stubber.add_response(
        'put_bucket_encryption',
        {},
        {
            'Bucket': 'so0111-aws-cloudtrail-111111111111',
            'ServerSideEncryptionConfiguration': {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': '1234abcd-12ab-34cd-56ef-1234567890ab'

                        }
                    }
                ]
            }
        }
    )

    s3_stubber.add_response(
        'put_public_access_block',
        {},
        {
            'Bucket': 'so0111-aws-cloudtrail-111111111111',
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        }
    )

    s3_stubber.add_response(
        'put_bucket_logging',
        {},
        {
            'Bucket': 'so0111-aws-cloudtrail-111111111111',
            'BucketLoggingStatus': {
                'LoggingEnabled': {
                    'TargetBucket': event['logging_bucket'],
                    'TargetPrefix': 'cloudtrail-access-logs'
                }
            }
        }
    )
    s3_stubber.activate()
    mocker.patch('CreateCloudTrailMultiRegionTrail_createcloudtrailbucket.connect_to_s3', return_value=s3)
    createcloudtrailbucket.create_encrypted_bucket(event, {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()

def test_bucket_already_exists(mocker):
    event = {
        'SolutionId': 'SO0000',
        'SolutionVersion': '1.2.3',
        'region': my_region,
        'kms_key_arn': 'arn:aws:kms:us-east-1:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab',
        'account': '111111111111',
        'logging_bucket': 'mah-loggin-bukkit'
    }
    BOTO_CONFIG = Config(
        retries ={
          'mode': 'standard'
        },
        region_name=my_region
    )
    s3 = botocore.session.get_session().create_client('s3', config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)
    kwargs = {
        'Bucket': 'so0111-aws-cloudtrail-111111111111',
        'ACL': 'private'
    }
    if my_region != 'us-east-1':
        kwargs['CreateBucketConfiguration'] = {
            'LocationConstraint': my_region
        }

    s3_stubber.add_client_error(
        'create_bucket',
        'BucketAlreadyExists'
    )

    s3_stubber.activate()
    mocker.patch('CreateCloudTrailMultiRegionTrail_createcloudtrailbucket.connect_to_s3', return_value=s3)
    assert createcloudtrailbucket.create_encrypted_bucket(event, {}) == { 'cloudtrail_bucket': 'so0111-aws-cloudtrail-111111111111' }
    s3_stubber.deactivate()

#=====================================================================================
# CreateCloudTrailMultiRegionTrail_createcloudtrailbucketpolicy
#=====================================================================================
def test_create_bucket_policy(mocker):
    event = {
        'SolutionId': 'SO0000',
        'SolutionVersion': '1.2.3',
        'region': my_region,
        'partition': 'aws',
        'account': '111111111111',
        'cloudtrail_bucket': 'mahbukkit'
    }
    bucket_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "cloudtrail.amazonaws.com"
                ]
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::mahbukkit"
        },
        {
            "Sid": "AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "cloudtrail.amazonaws.com"
                ]
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mahbukkit/AWSLogs/111111111111/*",
            "Condition": { 
                "StringEquals": { 
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]}
    BOTO_CONFIG = Config(
        retries ={
          'mode': 'standard'
        },
        region_name=my_region
    )
    s3 = botocore.session.get_session().create_client('s3', config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)
    kwargs = {
        'Bucket': 'so0111-aws-cloudtrail-111111111111',
        'ACL': 'private'
    }
    if my_region != 'us-east-1':
        kwargs['CreateBucketConfiguration'] = {
            'LocationConstraint': my_region
        }

    s3_stubber.add_response(
        'put_bucket_policy',
        {},
        {
            'Bucket': 'mahbukkit',
            'Policy': json.dumps(bucket_policy)
        }
    )

    s3_stubber.activate()
    mocker.patch('CreateCloudTrailMultiRegionTrail_createcloudtrailbucketpolicy.connect_to_s3', return_value=s3)
    createcloudtrailbucketpolicy.create_bucket_policy(event, {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()

#=====================================================================================
# CreateCloudTrailMultiRegionTrail_createloggingbucket
#=====================================================================================
def test_create_logging_bucket(mocker):
    event = {
        'SolutionId': 'SO0000',
        'SolutionVersion': '1.2.3',
        'region': my_region,
        'kms_key_arn': 'arn:aws:kms:us-east-1:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab',
        'account': '111111111111'
    }
    bucket_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "cloudtrail.amazonaws.com"
                ]
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::mahbukkit"
        },
        {
            "Sid": "AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "cloudtrail.amazonaws.com"
                ]
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::mahbukkit/AWSLogs/111111111111/*",
            "Condition": { 
                "StringEquals": { 
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]}
    BOTO_CONFIG = Config(
        retries ={
          'mode': 'standard'
        },
        region_name=my_region
    )
    s3 = botocore.session.get_session().create_client('s3', config=BOTO_CONFIG)

    kwargs = {
        'Bucket': 'so0111-access-logs-' + my_region + '-111111111111',
        'ACL': 'private'
    }
    if my_region != 'us-east-1':
        kwargs['CreateBucketConfiguration'] = {
            'LocationConstraint': my_region
        }
    s3_stubber = Stubber(s3)

    s3_stubber.add_response(
        'create_bucket',
        {},
        kwargs
    )

    s3_stubber.add_response(
        'put_bucket_encryption',
        {},
        {
            'Bucket': 'so0111-access-logs-' + my_region + '-111111111111',
            'ServerSideEncryptionConfiguration': {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': '1234abcd-12ab-34cd-56ef-1234567890ab'

                        }
                    }
                ]
            }
        }
    )

    s3_stubber.add_response(
        'put_public_access_block',
        {},
        {
            'Bucket': 'so0111-access-logs-' + my_region + '-111111111111',
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        }
    )

    s3_stubber.add_response(
        'put_bucket_acl',
        {},
        {
            'Bucket': 'so0111-access-logs-' + my_region + '-111111111111',
            'GrantReadACP': 'uri=http://acs.amazonaws.com/groups/s3/LogDelivery',
            'GrantWrite': 'uri=http://acs.amazonaws.com/groups/s3/LogDelivery'
        }
    )

    s3_stubber.activate()
    mocker.patch('CreateCloudTrailMultiRegionTrail_createloggingbucket.connect_to_s3', return_value=s3)
    createloggingbucket.create_logging_bucket(event, {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()

#=====================================================================================    
# CreateCloudTrailMultiRegionTrail_enablecloudtrail
#=====================================================================================
def test_enable_cloudtrail(mocker):
    event = {
        'SolutionId': 'SO0000',
        'SolutionVersion': '1.2.3',
        'region': my_region,
        'kms_key_arn': 'arn:aws:kms:us-east-1:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab',
        'cloudtrail_bucket': 'mahbukkit'
    }
    BOTO_CONFIG = Config(
        retries ={
          'mode': 'standard'
        },
        region_name=my_region
    )
    ct_client = botocore.session.get_session().create_client('cloudtrail', config=BOTO_CONFIG)
    ct_stubber = Stubber(ct_client)

    ct_stubber.add_response(
        'create_trail',
        {},
        {
            'Name': 'multi-region-cloud-trail',
            'S3BucketName': 'mahbukkit',
            'IncludeGlobalServiceEvents': True,
            'EnableLogFileValidation': True,
            'IsMultiRegionTrail': True,
            'KmsKeyId': 'arn:aws:kms:us-east-1:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab'
        }
    )

    ct_stubber.add_response(
        'start_logging',
        {},
        {
            'Name': 'multi-region-cloud-trail'
        }
    )

    ct_stubber.activate()
    mocker.patch('CreateCloudTrailMultiRegionTrail_enablecloudtrail.connect_to_cloudtrail', return_value=ct_client)
    enablecloudtrail.enable_cloudtrail(event, {})
    ct_stubber.assert_no_pending_responses()
    ct_stubber.deactivate()

#=====================================================================================    
# CreateCloudTrailMultiRegionTrail_process_results
#=====================================================================================
def test_process_results():
    event = {
        'cloudtrail_bucket': 'cloudtrail_logs_bucket',
        'logging_bucket': 'access_logs_bucket'
    }
    assert process_results.process_results(event, {}) == {
        "response": {
            "message": "AWS CloudTrail successfully enabled",
            "status": "Success"
        }
    }

#=====================================================================================
# Test inputs
#=====================================================================================
def test_put_bucket_acl_fails():
    """
    Verify proper exit when put_bucket_acl fails
    """

    s3 = botocore.session.get_session().create_client('s3')
    s3_stubber = Stubber(s3)
    s3_stubber.add_client_error(
        'put_bucket_acl',
        'ADoorIsAjar'
    )
    s3_stubber.activate()

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = createloggingbucket.put_bucket_acl(s3, 'mahbukkit')
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'Error setting ACL for bucket mahbukkit: An error occurred (ADoorIsAjar) when calling the PutBucketAcl operation: '

    s3_stubber.deactivate()

def test_put_access_blocks_fails():
    """
    Verify proper exit when put_public_access_blocks fails
    """

    s3 = botocore.session.get_session().create_client('s3')
    s3_stubber = Stubber(s3)
    s3_stubber.add_client_error(
        'put_public_access_block',
        'ADoorIsAjar'
    )
    s3_stubber.activate()

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = createloggingbucket.put_access_block(s3, 'mahbukkit')
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'Error setting public access block for bucket mahbukkit: An error occurred (ADoorIsAjar) when calling the PutPublicAccessBlock operation: '

    s3_stubber.deactivate()

def test_encrypt_bucket_fails():
    """
    Verify proper exit when put_bucket_encryption fails
    """

    s3 = botocore.session.get_session().create_client('s3')
    s3_stubber = Stubber(s3)
    s3_stubber.add_client_error(
        'put_bucket_encryption',
        'ADoorIsAjar'
    )
    s3_stubber.activate()

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parsed_event = createloggingbucket.encrypt_bucket(s3, 'mahbukkit', 'arn:aws:kms:us-east-1:111111111111:key/mahcryptionkey')
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 'Error encrypting bucket mahbukkit: An error occurred (ADoorIsAjar) when calling the PutBucketEncryption operation: '

    s3_stubber.deactivate()

