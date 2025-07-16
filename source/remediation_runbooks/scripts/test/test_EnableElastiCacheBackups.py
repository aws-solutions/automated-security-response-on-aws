# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import botocore.session
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from EnableElastiCacheBackups import handler

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup_stubber(mocker, client):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    mocker.patch("EnableElastiCacheBackups.get_elasticache_client", return_value=client)
    return client, stubber


def stub_modify_cache_cluster(stubber, cluster_id, retention_period):
    """Add modify_cache_cluster response to stubber"""
    modify_response = {
        "CacheCluster": {
            "CacheClusterId": cluster_id,
            "SnapshotRetentionLimit": retention_period,
        }
    }

    stubber.add_response(
        "modify_cache_cluster",
        modify_response,
        {"CacheClusterId": cluster_id, "SnapshotRetentionLimit": retention_period},
    )


def create_event(resource_arn: str, retention_period: int = 7) -> dict:
    """Create a standard event dictionary"""
    return {"ResourceARN": resource_arn, "SnapshotRetentionPeriod": retention_period}


def test_handler_successful_backup_enable(mocker):
    elasticache_client, stubber = setup_stubber(mocker, "elasticache")
    cluster_id = "test-cluster"
    cluster_arn = f"arn:aws:elasticache:us-east-1:123456789012:cluster:{cluster_id}"
    retention_period = 7

    stub_modify_cache_cluster(stubber, cluster_id, retention_period)

    with stubber:
        response = handler(create_event(cluster_arn, retention_period), None)

    assert response["Status"] == "success"
    assert (
        f"Successfully enabled backups for cluster {cluster_arn}" in response["Message"]
    )
    stubber.assert_no_pending_responses()


def test_handler_replication_group(mocker):
    elasticache_client, stubber = setup_stubber(mocker, "elasticache")
    replication_group_id = "test-group"
    replication_group_arn = f"arn:aws:elasticache:us-east-1:123456789012:replicationgroup:{replication_group_id}"
    retention_period = 7

    # Stub describe_replication_groups response
    describe_response = {
        "ReplicationGroups": [
            {
                "ReplicationGroupId": replication_group_id,
                "ClusterMode": "disabled",
                "NodeGroups": [
                    {"NodeGroupMembers": [{"CacheClusterId": "test-cluster-001"}]}
                ],
            }
        ]
    }
    stubber.add_response(
        "describe_replication_groups",
        describe_response,
        {"ReplicationGroupId": replication_group_id},
    )

    # Stub modify_replication_group response
    modify_response = {
        "ReplicationGroup": {
            "ReplicationGroupId": replication_group_id,
            "SnapshotRetentionLimit": retention_period,
        }
    }
    stubber.add_response(
        "modify_replication_group",
        modify_response,
        {
            "ReplicationGroupId": replication_group_id,
            "SnapshotRetentionLimit": retention_period,
            "SnapshottingClusterId": "test-cluster-001",
        },
    )

    with stubber:
        response = handler(create_event(replication_group_arn, retention_period), None)

    assert response["Status"] == "success"
    assert replication_group_arn in response["Message"]
    stubber.assert_no_pending_responses()


def test_handler_replication_group_enabled_cluster_mode(mocker):
    elasticache_client, stubber = setup_stubber(mocker, "elasticache")
    replication_group_id = "test-group"
    replication_group_arn = f"arn:aws:elasticache:us-east-1:123456789012:replicationgroup:{replication_group_id}"
    retention_period = 7

    # Stub describe_replication_groups response with disabled cluster mode
    describe_response = {
        "ReplicationGroups": [
            {
                "ReplicationGroupId": replication_group_id,
                "ClusterMode": "enabled",
                "NodeGroups": [
                    {"NodeGroupMembers": [{"CacheClusterId": "test-cluster-001"}]}
                ],
            }
        ]
    }
    stubber.add_response(
        "describe_replication_groups",
        describe_response,
        {"ReplicationGroupId": replication_group_id},
    )

    # Stub modify_replication_group response
    modify_response = {
        "ReplicationGroup": {
            "ReplicationGroupId": replication_group_id,
            "SnapshotRetentionLimit": retention_period,
        }
    }
    stubber.add_response(
        "modify_replication_group",
        modify_response,
        {
            "ReplicationGroupId": replication_group_id,
            "SnapshotRetentionLimit": retention_period,
        },
    )

    with stubber:
        response = handler(create_event(replication_group_arn, retention_period), None)

    assert response["Status"] == "success"
    assert replication_group_arn in response["Message"]
    stubber.assert_no_pending_responses()


def test_handler_invalid_resource_type(mocker):
    elasticache_client, stubber = setup_stubber(mocker, "elasticache")
    invalid_arn = "arn:aws:elasticache:us-east-1:123456789012:invalid:test-resource"
    retention_period = 7

    with stubber:
        with pytest.raises(RuntimeError) as exc_info:
            handler(create_event(invalid_arn, retention_period), None)

    assert "Invalid resource type" in str(exc_info.value)
    stubber.assert_no_pending_responses()


def test_handler_cluster_error(mocker):
    elasticache_client, stubber = setup_stubber(mocker, "elasticache")
    cluster_id = "test-cluster"
    cluster_arn = f"arn:aws:elasticache:us-east-1:123456789012:cluster:{cluster_id}"
    retention_period = 7

    stubber.add_client_error(
        "modify_cache_cluster",
        "InvalidCacheClusterState",
        "Cluster is not in available state",
    )

    with stubber:
        with pytest.raises(RuntimeError) as exc_info:
            handler(create_event(cluster_arn, retention_period), None)

    assert f"Failed to enable backups for cluster {cluster_id}" in str(exc_info.value)
    stubber.assert_no_pending_responses()


def test_handler_replication_group_error(mocker):
    elasticache_client, stubber = setup_stubber(mocker, "elasticache")
    replication_group_id = "test-group"
    replication_group_arn = f"arn:aws:elasticache:us-east-1:123456789012:replicationgroup:{replication_group_id}"
    retention_period = 7

    stubber.add_client_error(
        "describe_replication_groups",
        "ReplicationGroupNotFoundFault",
        "Replication group not found",
    )

    with stubber:
        with pytest.raises(RuntimeError) as exc_info:
            handler(create_event(replication_group_arn, retention_period), None)

    assert (
        f"Failed to enable backups for replication group {replication_group_id}"
        in str(exc_info.value)
    )
    stubber.assert_no_pending_responses()
