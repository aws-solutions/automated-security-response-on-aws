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

def connect_to_rds():
    boto_config = Config(
        retries ={
            'mode': 'standard'
        }
    )
    return boto3.client('rds', config=boto_config)

def make_snapshot_private(event, context):

    rds_client = connect_to_rds()
    snapshot_id = event['DBSnapshotId']
    snapshot_type = event['DBSnapshotType']
    try:
        if (snapshot_type == 'snapshot'):
            rds_client.modify_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot_id,
                AttributeName='restore',
                ValuesToRemove=['all']
            )
        elif (snapshot_type == 'cluster-snapshot'):
            rds_client.modify_db_cluster_snapshot_attribute(
                DBClusterSnapshotIdentifier=snapshot_id,
                AttributeName='restore',
                ValuesToRemove=['all']
            )
        else:
            exit(f'Unrecognized snapshot_type {snapshot_type}')

        print(f'Remediation completed: {snapshot_id} public access removed.')
        return {
            "response": {
                "message": f'Snapshot {snapshot_id} permissions set to private',
                "status": "Success"
            }
        }
    except Exception as e:
        exit(f'Remediation failed for {snapshot_id}: {str(e)}')
