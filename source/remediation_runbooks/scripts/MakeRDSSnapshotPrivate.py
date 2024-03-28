# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config


def connect_to_rds():
    boto_config = Config(retries={"mode": "standard"})
    return boto3.client("rds", config=boto_config)


def make_snapshot_private(event, _):
    rds_client = connect_to_rds()
    snapshot_id = event["DBSnapshotId"]
    snapshot_type = event["DBSnapshotType"]
    try:
        if snapshot_type == "snapshot":
            rds_client.modify_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot_id,
                AttributeName="restore",
                ValuesToRemove=["all"],
            )
        elif snapshot_type == "cluster-snapshot":
            rds_client.modify_db_cluster_snapshot_attribute(
                DBClusterSnapshotIdentifier=snapshot_id,
                AttributeName="restore",
                ValuesToRemove=["all"],
            )
        else:
            exit(f"Unrecognized snapshot_type {snapshot_type}")

        print(f"Remediation completed: {snapshot_id} public access removed.")
        return {
            "response": {
                "message": f"Snapshot {snapshot_id} permissions set to private",
                "status": "Success",
            }
        }
    except Exception as e:
        exit(f"Remediation failed for {snapshot_id}: {str(e)}")
