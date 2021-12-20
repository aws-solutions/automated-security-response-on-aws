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

def connect_to_ec2(boto_config):
    return boto3.client('ec2', config=boto_config)

def get_public_snapshots(event, context):
    account_id = event['account_id']

    if 'testmode' in event and event['testmode']:
        return [
            "snap-12341234123412345",
            "snap-12341234123412345",
            "snap-12341234123412345",
            "snap-12341234123412345",
            "snap-12341234123412345"
        ]

    return list_public_snapshots(account_id)

def list_public_snapshots(account_id):
    ec2 = connect_to_ec2(boto_config)
    control_token = 'start'
    try:

        public_snapshot_ids = []

        while control_token:

            if control_token == 'start': # needed a value to start the loop. Now reset it
                control_token = ''

            kwargs = {
                'MaxResults': 100, 
                'OwnerIds': [ account_id ],
                'RestorableByUserIds': [ 'all' ]
            }
            if control_token:
                kwargs['NextToken'] = control_token
                
            response = ec2.describe_snapshots(
                        **kwargs
                )
        
            for snapshot in response['Snapshots']:
                public_snapshot_ids.append(snapshot['SnapshotId'])

            if 'NextToken' in response:
                control_token = response['NextToken']
            else:
                control_token = ''

        return public_snapshot_ids
        
    except Exception as e:
        print(e)
        exit('Failed to describe_snapshots')
