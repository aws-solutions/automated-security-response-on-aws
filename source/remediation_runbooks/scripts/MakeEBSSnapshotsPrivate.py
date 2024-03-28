# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
from botocore.config import Config


def connect_to_ec2(boto_config):
    return boto3.client("ec2", config=boto_config)


def make_snapshots_private(event, _):
    boto_config = Config(retries={"mode": "standard", "max_attempts": 10})
    ec2 = connect_to_ec2(boto_config)

    remediated = []
    snapshots = event["snapshots"]

    success_count = 0

    for snapshot_id in snapshots:
        try:
            ec2.modify_snapshot_attribute(
                Attribute="CreateVolumePermission",
                CreateVolumePermission={"Remove": [{"Group": "all"}]},
                SnapshotId=snapshot_id,
            )
            print(f"Snapshot {snapshot_id} permissions set to private")

            remediated.append(snapshot_id)
            success_count += 1
        except Exception as e:
            print(e)
            print(f"FAILED to remediate Snapshot {snapshot_id}")

    result = json.dumps(
        ec2.describe_snapshots(SnapshotIds=remediated), indent=2, default=str
    )
    print(result)

    return {
        "response": {
            "message": f"{success_count} of {len(snapshots)} Snapshot permissions set to private",
            "status": "Success",
        }
    }
