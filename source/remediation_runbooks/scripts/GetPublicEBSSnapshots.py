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
            {
                "Description": "Snapshot of idle volume before deletion",
                "Encrypted": False,
                "OwnerId": "111111111111",
                "Progress": "100%",
                "SnapshotId": "snap-12341234123412345",
                "StartTime": "2021-03-11T08:23:02.785Z",
                "State": "completed",
                "VolumeId": "vol-12341234123412345",
                "VolumeSize": 4,
                "Tags": [
                    {
                        "Key": "SnapshotDate",
                        "Value": "2021-03-11 08:23:02.376859"
                    },
                    {
                        "Key": "DeleteEBSVolOnCompletion",
                        "Value": "False"
                    },
                    {
                        "Key": "SnapshotReason",
                        "Value": "Idle Volume"
                    }
                ]
            },
            {
                "Description": "Snapshot of idle volume before deletion",
                "Encrypted": False,
                "OwnerId": "111111111111",
                "Progress": "100%",
                "SnapshotId": "snap-12341234123412345",
                "StartTime": "2021-03-11T08:20:37.399Z",
                "State": "completed",
                "VolumeId": "vol-12341234123412345",
                "VolumeSize": 4,
                "Tags": [
                    {
                        "Key": "DeleteEBSVolOnCompletion",
                        "Value": "False"
                    },
                    {
                        "Key": "SnapshotDate",
                        "Value": "2021-03-11 08:20:37.224101"
                    },
                    {
                        "Key": "SnapshotReason",
                        "Value": "Idle Volume"
                    }
                ]
            },
            {
                "Description": "Snapshot of idle volume before deletion",
                "Encrypted": False,
                "OwnerId": "111111111111",
                "Progress": "100%",
                "SnapshotId": "snap-12341234123412345",
                "StartTime": "2021-03-11T08:22:48.936Z",
                "State": "completed",
                "VolumeId": "vol-12341234123412345",
                "VolumeSize": 4,
                "Tags": [
                    {
                        "Key": "SnapshotReason",
                        "Value": "Idle Volume"
                    },
                    {
                        "Key": "SnapshotDate",
                        "Value": "2021-03-11 08:22:48.714893"
                    },
                    {
                        "Key": "DeleteEBSVolOnCompletion",
                        "Value": "False"
                    }
                ]
            },
            {
                "Description": "Snapshot of idle volume before deletion",
                "Encrypted": False,
                "OwnerId": "111111111111",
                "Progress": "100%",
                "SnapshotId": "snap-12341234123412345",
                "StartTime": "2021-03-11T08:23:05.156Z",
                "State": "completed",
                "VolumeId": "vol-12341234123412345",
                "VolumeSize": 4,
                "Tags": [
                    {
                        "Key": "DeleteEBSVolOnCompletion",
                        "Value": "False"
                    },
                    {
                        "Key": "SnapshotReason",
                        "Value": "Idle Volume"
                    },
                    {
                        "Key": "SnapshotDate",
                        "Value": "2021-03-11 08:23:04.876640"
                    }
                ]
            },
            {
                "Description": "Snapshot of idle volume before deletion",
                "Encrypted": False,
                "OwnerId": "111111111111",
                "Progress": "100%",
                "SnapshotId": "snap-12341234123412345",
                "StartTime": "2021-03-11T08:22:34.850Z",
                "State": "completed",
                "VolumeId": "vol-12341234123412345",
                "VolumeSize": 4,
                "Tags": [
                    {
                        "Key": "DeleteEBSVolOnCompletion",
                        "Value": "False"
                    },
                    {
                        "Key": "SnapshotReason",
                        "Value": "Idle Volume"
                    },
                    {
                        "Key": "SnapshotDate",
                        "Value": "2021-03-11 08:22:34.671355"
                    }
                ]
            }
        ]

    return list_public_snapshots(account_id)

def list_public_snapshots(account_id):
    ec2 = connect_to_ec2(boto_config)
    control_token = 'start'
    try:

        buffer = []

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

            if 'NextToken' in response:
                control_token = response['NextToken']
            else:
                control_token = ''

            buffer += response['Snapshots']

        return buffer
    except Exception as e:
        print(e)
        exit('Failed to describe_snapshots')
