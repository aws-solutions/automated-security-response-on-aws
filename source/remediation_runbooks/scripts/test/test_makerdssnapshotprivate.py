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
from botocore.stub import Stubber, ANY
from botocore.config import Config
import pytest
from pytest_mock import mocker

import MakeRDSSnapshotPrivate as remediate

my_session = boto3.session.Session()
my_region = my_session.region_name

BOTO_CONFIG = Config(
    retries ={
        'mode': 'standard'
    },
    region_name=my_region
)

db_snap_event = {
    'DBSnapshotId': 'snap-111111111111',
    'DBSnapshotType': 'snapshot'
}

cluster_snap_event = {
    'DBSnapshotId': 'snap-111111111111',
    'DBSnapshotType': 'cluster-snapshot'
}

def test_make_clustersnap_private(mocker):
    event = cluster_snap_event
    rds = botocore.session.get_session().create_client('rds', config=BOTO_CONFIG)
    rds_stubber = Stubber(rds)
    rds_stubber.add_response(
        'modify_db_cluster_snapshot_attribute',
        {}
    )
    rds_stubber.activate()
    mocker.patch('MakeRDSSnapshotPrivate.connect_to_rds', return_value=rds)
    assert remediate.make_snapshot_private(event, {}) == {
            "response": {
                "message": "Snapshot snap-111111111111 permissions set to private",
                "status": "Success"
            }
        }
    rds_stubber.assert_no_pending_responses()
    rds_stubber.deactivate()

def test_make_db_private(mocker):
    event = db_snap_event
    rds = botocore.session.get_session().create_client('rds', config=BOTO_CONFIG)
    rds_stubber = Stubber(rds)
    rds_stubber.add_response(
        'modify_db_snapshot_attribute',
        {}
    )
    rds_stubber.activate()
    mocker.patch('MakeRDSSnapshotPrivate.connect_to_rds', return_value=rds)
    assert remediate.make_snapshot_private(event, {}) == {
            "response": {
                "message": "Snapshot snap-111111111111 permissions set to private",
                "status": "Success"
            }
        }
    rds_stubber.assert_no_pending_responses()
    rds_stubber.deactivate()
