# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


def get_elasticache_client():
    return boto3.client("elasticache", config=boto_config)


class Event(TypedDict):
    ResourceARN: str
    SnapshotRetentionPeriod: int


class Response(TypedDict):
    Message: str
    Status: str


def handler(event: Event, _) -> Response:
    """
    Remediates ElastiCache.1 by enabling automatic backups.
    """
    try:
        resource_arn = event["ResourceARN"]
        snapshot_retention_period = event["SnapshotRetentionPeriod"]

        resource_type = resource_arn.split(":")[5]

        if resource_type.lower() == "cluster":
            cluster_id = resource_arn.split(":")[-1]
            enable_cluster_backups(cluster_id, snapshot_retention_period)
        elif resource_type.lower() == "replicationgroup":
            resource_group_id = resource_arn.split(":")[-1]
            enable_replication_group_backups(
                resource_group_id, snapshot_retention_period
            )
        else:
            raise RuntimeError(f"Invalid resource type: {resource_type}")
        return {
            "Message": (f"Successfully enabled backups for cluster {resource_arn}."),
            "Status": "success",
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error enabling automatic backups for ElastiCache cluster: {str(e)}"
        )


def enable_cluster_backups(
    cluster_identifier: str, snapshot_retention_period: int
) -> None:
    try:
        elasticache_client = get_elasticache_client()
        elasticache_client.modify_cache_cluster(
            CacheClusterId=cluster_identifier,
            SnapshotRetentionLimit=snapshot_retention_period,
        )
    except Exception as e:
        raise RuntimeError(
            f"Failed to enable backups for cluster {cluster_identifier}: {str(e)}"
        )


def enable_replication_group_backups(
    replication_group_id: str, snapshot_retention_period: int
) -> None:
    try:
        elasticache_client = get_elasticache_client()

        replication_group_details = elasticache_client.describe_replication_groups(
            ReplicationGroupId=replication_group_id
        )["ReplicationGroups"][0]

        if replication_group_details["ClusterMode"] == "disabled":
            snapshotting_cluster_id = replication_group_details["NodeGroups"][0][
                "NodeGroupMembers"
            ][0]["CacheClusterId"]
            elasticache_client.modify_replication_group(
                ReplicationGroupId=replication_group_id,
                SnapshotRetentionLimit=snapshot_retention_period,
                SnapshottingClusterId=snapshotting_cluster_id,
            )
        else:
            elasticache_client.modify_replication_group(
                ReplicationGroupId=replication_group_id,
                SnapshotRetentionLimit=snapshot_retention_period,
            )
    except Exception as e:
        raise RuntimeError(
            f"Failed to enable backups for replication group {replication_group_id}: {str(e)}"
        )
