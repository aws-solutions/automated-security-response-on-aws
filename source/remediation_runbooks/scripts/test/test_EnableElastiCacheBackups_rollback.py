# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for ElastiCache.1 — EnableElastiCacheBackups rollback script.

moto does not implement elasticache modify_cache_cluster / modify_replication_group, so ElastiCache is
served by an in-memory FakeElastiCache routed through boto3.client; S3 still uses moto. State is the
integer SnapshotRetentionLimit (0 = backups disabled), on a cache cluster or a replication group.
"""
from __future__ import annotations

import json
from typing import Any

import boto3
import EnableElastiCacheBackups_rollback as rollback
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from moto import mock_aws
from pytest_mock import MockerFixture

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "ElastiCache.1"
ACCOUNT_ID = "123456789012"
CLUSTER_ID = "test-cluster"
CLUSTER_ARN = "arn:aws:elasticache:us-east-1:123456789012:cluster:test-cluster"
REPLICATION_GROUP_ID = "test-group"
REPLICATION_GROUP_ARN = (
    "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:test-group"
)


class FakeElastiCache:
    """In-memory ElastiCache stand-in (moto doesn't implement the modify_* actions)."""

    def __init__(self) -> None:
        self.clusters: dict[str, int] = {}
        self.replication_groups: dict[str, dict[str, Any]] = {}
        self.modify_cache_cluster_calls: list[dict[str, Any]] = []
        self.modify_replication_group_calls: list[dict[str, Any]] = []

    def add_cluster(self, cluster_id: str, retention: int) -> None:
        self.clusters[cluster_id] = retention

    def add_replication_group(
        self,
        replication_group_id: str,
        retention: int,
        *,
        cluster_mode: str = "disabled",
        snapshotting_cluster_id: str = "test-group-001",
    ) -> None:
        self.replication_groups[replication_group_id] = {
            "SnapshotRetentionLimit": retention,
            "ClusterMode": cluster_mode,
            "NodeGroups": [
                {"NodeGroupMembers": [{"CacheClusterId": snapshotting_cluster_id}]}
            ],
        }

    def describe_cache_clusters(
        self, *, CacheClusterId: str
    ) -> dict[str, Any]:  # noqa: N803 boto3 API kwarg
        if CacheClusterId not in self.clusters:
            raise ClientError(
                {
                    "Error": {
                        "Code": "CacheClusterNotFound",
                        "Message": f"{CacheClusterId} not found",
                    }
                },
                "DescribeCacheClusters",
            )
        return {
            "CacheClusters": [
                {
                    "CacheClusterId": CacheClusterId,
                    "SnapshotRetentionLimit": self.clusters[CacheClusterId],
                }
            ]
        }

    def modify_cache_cluster(
        self, *, CacheClusterId: str, SnapshotRetentionLimit: int
    ) -> dict[str, Any]:
        if CacheClusterId not in self.clusters:
            raise ClientError(
                {
                    "Error": {
                        "Code": "CacheClusterNotFound",
                        "Message": f"{CacheClusterId} not found",
                    }
                },
                "ModifyCacheCluster",
            )
        self.modify_cache_cluster_calls.append(
            {
                "CacheClusterId": CacheClusterId,
                "SnapshotRetentionLimit": SnapshotRetentionLimit,
            }
        )
        self.clusters[CacheClusterId] = SnapshotRetentionLimit
        return {"CacheCluster": {"CacheClusterId": CacheClusterId}}

    def describe_replication_groups(
        self, *, ReplicationGroupId: str
    ) -> dict[str, Any]:  # noqa: N803 boto3 API kwarg
        if ReplicationGroupId not in self.replication_groups:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ReplicationGroupNotFoundFault",
                        "Message": f"{ReplicationGroupId} not found",
                    }
                },
                "DescribeReplicationGroups",
            )
        return {
            "ReplicationGroups": [
                {
                    "ReplicationGroupId": ReplicationGroupId,
                    **self.replication_groups[ReplicationGroupId],
                }
            ]
        }

    def modify_replication_group(
        self,
        *,
        ReplicationGroupId: str,  # noqa: N803 boto3 API kwarg
        SnapshotRetentionLimit: int,  # noqa: N803 boto3 API kwarg
        SnapshottingClusterId: str = "",  # noqa: N803 boto3 API kwarg
    ) -> dict[str, Any]:
        if ReplicationGroupId not in self.replication_groups:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ReplicationGroupNotFoundFault",
                        "Message": f"{ReplicationGroupId} not found",
                    }
                },
                "ModifyReplicationGroup",
            )
        # Record exactly what was passed: SnapshottingClusterId is only sent when enabling backups on a
        # cluster-mode-disabled group, and the tests assert on its presence or absence.
        call: dict[str, Any] = {
            "ReplicationGroupId": ReplicationGroupId,
            "SnapshotRetentionLimit": SnapshotRetentionLimit,
        }
        if SnapshottingClusterId:
            call["SnapshottingClusterId"] = SnapshottingClusterId
        self.modify_replication_group_calls.append(call)
        self.replication_groups[ReplicationGroupId][
            "SnapshotRetentionLimit"
        ] = SnapshotRetentionLimit
        return {"ReplicationGroup": {"ReplicationGroupId": ReplicationGroupId}}


@pytest.fixture
def fake_elasticache(mocker: MockerFixture) -> FakeElastiCache:
    """Route boto3.client('elasticache') to the fake; everything else (S3) stays on moto."""
    fake = FakeElastiCache()
    original_client = boto3.client
    mocker.patch.object(
        rollback.boto3,
        "client",
        side_effect=lambda service, *args, **kwargs: (
            fake
            if service == "elasticache"
            else original_client(service, *args, **kwargs)
        ),
    )
    return fake


def _create_snapshot_bucket() -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=SNAPSHOT_BUCKET)
    s3.put_bucket_versioning(
        Bucket=SNAPSHOT_BUCKET, VersioningConfiguration={"Status": "Enabled"}
    )


def _snapshot_key(execution_id: str = EXECUTION_ID) -> str:
    return f"snapshots/{execution_id}/{CONTROL_ID}.json"


def _put_snapshot(
    execution_id: str,
    *,
    pre_retention: int,
    post_retention: int = 1,
    resource_id: str = CLUSTER_ARN,
    schema_version: int = 1,
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    snapshot_data = {
        "schemaVersion": schema_version,
        "resourceId": resource_id,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"SnapshotRetentionLimit": pre_retention},
        "postRemediationState": {"SnapshotRetentionLimit": post_retention},
    }
    response = s3.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=_snapshot_key(execution_id),
        Body=json.dumps(snapshot_data),
        ContentType="application/json",
    )
    return response["VersionId"]


def _make_capture_event(
    *,
    resource_arn: str = CLUSTER_ARN,
    bucket: str = SNAPSHOT_BUCKET,
    execution_id: str = EXECUTION_ID,
    retention: int = 1,
) -> dict[str, object]:
    return {
        "ResourceARN": resource_arn,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
        "SnapshotRetentionPeriod": retention,
    }


def _make_rollback_event(
    *,
    resource_arn: str = CLUSTER_ARN,
    execution_id: str = EXECUTION_ID,
    snapshot_version_id: str = "",
) -> dict[str, object]:
    return {
        "ResourceARN": resource_arn,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": execution_id,
        "SnapshotVersionId": snapshot_version_id,
    }


# ── unit: ARN parsing + retention parsing ────────────────────────────────────


def test_validate_resource_arn_cluster_and_replicationgroup() -> None:
    assert rollback._validate_resource_arn(
        {"ResourceARN": CLUSTER_ARN}, ACCOUNT_ID
    ) == {
        "kind": "cluster",
        "identifier": CLUSTER_ID,
    }
    assert rollback._validate_resource_arn(
        {"ResourceARN": REPLICATION_GROUP_ARN}, ACCOUNT_ID
    ) == {
        "kind": "replicationgroup",
        "identifier": REPLICATION_GROUP_ID,
    }


def test_validate_resource_arn_rejects_bad_type_and_cross_account() -> None:
    with pytest.raises(ValueError, match="expected an ElastiCache"):
        rollback._validate_resource_arn(
            {
                "ResourceARN": "arn:aws:elasticache:us-east-1:123456789012:serverlesscache:x"
            },
            ACCOUNT_ID,
        )
    with pytest.raises(ValueError, match="does not match the executing account"):
        rollback._validate_resource_arn(
            {"ResourceARN": "arn:aws:elasticache:us-east-1:999999999999:cluster:x"},
            ACCOUNT_ID,
        )
    with pytest.raises(ValueError, match="expected an ElastiCache"):
        rollback._validate_resource_arn(
            {"ResourceARN": "arn:aws:elasticache::123456789012:cluster:x"}, ACCOUNT_ID
        )


def test_validate_retention_validates() -> None:
    assert rollback._validate_retention(7) == 7
    assert rollback._validate_retention("5") == 5
    for bad in (0, -1, True, None, "nope"):
        with pytest.raises(ValueError, match="SnapshotRetentionPeriod"):
            rollback._validate_retention(bad)


# ── capture_and_remediate ────────────────────────────────────────────────────


class TestCaptureAndRemediate:
    @mock_aws
    def test_cluster_successful_snapshot_and_remediation(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        fake_elasticache.add_cluster(CLUSTER_ID, 0)
        result = rollback.capture_and_remediate(_make_capture_event(retention=1), None)
        assert result["snapshotStored"] == "true"
        assert "Restore SnapshotRetentionLimit to 0" in result["rollbackDescription"]
        assert fake_elasticache.clusters[CLUSTER_ID] == 1
        assert fake_elasticache.modify_cache_cluster_calls == [
            {"CacheClusterId": CLUSTER_ID, "SnapshotRetentionLimit": 1}
        ]
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snap = json.loads(
            s3.get_object(Bucket=SNAPSHOT_BUCKET, Key=_snapshot_key())["Body"].read()
        )
        assert snap["preRemediationState"]["SnapshotRetentionLimit"] == 0
        assert snap["postRemediationState"]["SnapshotRetentionLimit"] == 1
        assert snap["resourceId"] == CLUSTER_ARN

    @mock_aws
    def test_no_op_when_already_at_target(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        result = rollback.capture_and_remediate(_make_capture_event(retention=1), None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "No remediation needed" in result["rollbackDescription"]
        # Already compliant: no modify and no snapshot (matches ElastiCache.2's no-op path).
        assert fake_elasticache.modify_cache_cluster_calls == []
        assert fake_elasticache.clusters[CLUSTER_ID] == 1
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        assert (
            s3.list_objects_v2(
                Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
            ).get("KeyCount", 0)
            == 0
        )

    @mock_aws
    def test_no_op_when_above_target_does_not_downgrade(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # SnapshotRetentionPeriod is a minimum: a resource already above it must not be downgraded.
        _create_snapshot_bucket()
        fake_elasticache.add_cluster(CLUSTER_ID, 30)
        result = rollback.capture_and_remediate(_make_capture_event(retention=1), None)
        assert result["snapshotStored"] == "false"
        assert "No remediation needed" in result["rollbackDescription"]
        assert fake_elasticache.modify_cache_cluster_calls == []
        assert fake_elasticache.clusters[CLUSTER_ID] == 30

    @mock_aws
    def test_fail_open_when_bucket_missing(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        fake_elasticache.add_cluster(CLUSTER_ID, 0)
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="nonexistent-bucket", retention=1), None
        )
        assert result["snapshotStored"] == "false"
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert fake_elasticache.clusters[CLUSTER_ID] == 1

    @mock_aws
    def test_transient_describe_error_propagates(
        self, fake_elasticache: FakeElastiCache, mocker: MockerFixture
    ) -> None:
        # The current-state read is required for the minimum decision: a transient describe error must
        # propagate (fail the remediation, to be retried) rather than blindly set the target and risk
        # downgrading a retention we could not read.
        _create_snapshot_bucket()
        fake_elasticache.add_cluster(CLUSTER_ID, 0)
        throttle = ClientError(
            {"Error": {"Code": "Throttling", "Message": "rate exceeded"}},
            "DescribeCacheClusters",
        )
        mocker.patch.object(
            fake_elasticache, "describe_cache_clusters", side_effect=throttle
        )
        with pytest.raises(ClientError):
            rollback.capture_and_remediate(_make_capture_event(retention=1), None)
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_absent_retention_field_raises(
        self, fake_elasticache: FakeElastiCache, mocker: MockerFixture
    ) -> None:
        _create_snapshot_bucket()
        fake_elasticache.add_cluster(CLUSTER_ID, 0)
        mocker.patch.object(
            fake_elasticache,
            "describe_cache_clusters",
            return_value={"CacheClusters": [{"CacheClusterId": CLUSTER_ID}]},
        )
        with pytest.raises(
            rollback.ElastiCacheResponseError, match="no integer SnapshotRetentionLimit"
        ):
            rollback.capture_and_remediate(_make_capture_event(retention=1), None)
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_unversioned_bucket_reports_rollback_unavailable(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        boto3.client("s3", config=BOTO_CONFIG).create_bucket(
            Bucket=SNAPSHOT_BUCKET
        )  # no versioning
        fake_elasticache.add_cluster(CLUSTER_ID, 0)
        result = rollback.capture_and_remediate(_make_capture_event(retention=1), None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert fake_elasticache.clusters[CLUSTER_ID] == 1

    @mock_aws
    def test_missing_resource_raises_not_found(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        with pytest.raises(rollback.ResourceNotFoundError, match="not found"):
            rollback.capture_and_remediate(_make_capture_event(retention=1), None)
        assert fake_elasticache.modify_cache_cluster_calls == []
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        assert (
            s3.list_objects_v2(
                Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
            ).get("KeyCount", 0)
            == 0
        )

    @mock_aws
    def test_replicationgroup_disabled_mode_passes_snapshotting_cluster(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        fake_elasticache.add_replication_group(
            REPLICATION_GROUP_ID,
            0,
            cluster_mode="disabled",
            snapshotting_cluster_id="test-group-001",
        )
        result = rollback.capture_and_remediate(
            _make_capture_event(resource_arn=REPLICATION_GROUP_ARN, retention=1), None
        )
        assert result["snapshotStored"] == "true"
        assert (
            fake_elasticache.replication_groups[REPLICATION_GROUP_ID][
                "SnapshotRetentionLimit"
            ]
            == 1
        )
        assert fake_elasticache.modify_replication_group_calls == [
            {
                "ReplicationGroupId": REPLICATION_GROUP_ID,
                "SnapshotRetentionLimit": 1,
                "SnapshottingClusterId": "test-group-001",
            }
        ]

    @mock_aws
    def test_replicationgroup_enabled_mode_omits_snapshotting_cluster(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        fake_elasticache.add_replication_group(
            REPLICATION_GROUP_ID, 0, cluster_mode="enabled"
        )
        rollback.capture_and_remediate(
            _make_capture_event(resource_arn=REPLICATION_GROUP_ARN, retention=1), None
        )
        assert fake_elasticache.modify_replication_group_calls == [
            {"ReplicationGroupId": REPLICATION_GROUP_ID, "SnapshotRetentionLimit": 1}
        ]

    @mock_aws
    def test_replicationgroup_missing_node_group_members_raises(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # A cluster-mode-disabled RG with an empty NodeGroups shape gives a clear error, not an opaque IndexError.
        _create_snapshot_bucket()
        fake_elasticache.replication_groups[REPLICATION_GROUP_ID] = {
            "SnapshotRetentionLimit": 0,
            "ClusterMode": "disabled",
            "NodeGroups": [],
        }
        with pytest.raises(
            rollback.ElastiCacheResponseError, match="no node group members"
        ):
            rollback.capture_and_remediate(
                _make_capture_event(resource_arn=REPLICATION_GROUP_ARN, retention=1),
                None,
            )

    @mock_aws
    def test_replicationgroup_member_missing_cache_cluster_id_raises(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # A node group member lacking CacheClusterId gives a clear error, not an opaque KeyError.
        _create_snapshot_bucket()
        fake_elasticache.replication_groups[REPLICATION_GROUP_ID] = {
            "SnapshotRetentionLimit": 0,
            "ClusterMode": "disabled",
            "NodeGroups": [{"NodeGroupMembers": [{}]}],
        }
        with pytest.raises(
            rollback.ElastiCacheResponseError, match="no CacheClusterId"
        ):
            rollback.capture_and_remediate(
                _make_capture_event(resource_arn=REPLICATION_GROUP_ARN, retention=1),
                None,
            )

    @mock_aws
    def test_missing_resource_arn_raises(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
            "SnapshotRetentionPeriod": 1,
        }
        with pytest.raises(ValueError, match="expected an ElastiCache"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_invalid_account_id_raises(self, fake_elasticache: FakeElastiCache) -> None:
        with pytest.raises(ValueError, match="12-digit AWS account ID"):
            rollback.capture_and_remediate(
                {**_make_capture_event(), "AccountId": "123"}, None
            )

    @mock_aws
    def test_invalid_retention_raises(self, fake_elasticache: FakeElastiCache) -> None:
        with pytest.raises(ValueError, match="SnapshotRetentionPeriod"):
            rollback.capture_and_remediate(
                {**_make_capture_event(), "SnapshotRetentionPeriod": 0}, None
            )


# ── execute_rollback ─────────────────────────────────────────────────────────


class TestExecuteRollback:
    @mock_aws
    def test_cluster_successful_restore(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_retention=0, post_retention=1)
        fake_elasticache.add_cluster(
            CLUSTER_ID, 1
        )  # currently in post-remediation state
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "Successfully restored SnapshotRetentionLimit to 0" in result["Message"]
        assert fake_elasticache.clusters[CLUSTER_ID] == 0

    @mock_aws
    def test_replicationgroup_successful_restore(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID,
            pre_retention=0,
            post_retention=1,
            resource_id=REPLICATION_GROUP_ARN,
        )
        fake_elasticache.add_replication_group(
            REPLICATION_GROUP_ID, 1, cluster_mode="enabled"
        )
        result = rollback.execute_rollback(
            _make_rollback_event(
                resource_arn=REPLICATION_GROUP_ARN, snapshot_version_id=version_id
            ),
            None,
        )
        assert result["Status"] == "SUCCESS"
        assert (
            fake_elasticache.replication_groups[REPLICATION_GROUP_ID][
                "SnapshotRetentionLimit"
            ]
            == 0
        )

    @mock_aws
    def test_absent_retention_field_raises_instead_of_noop(
        self, fake_elasticache: FakeElastiCache, mocker: MockerFixture
    ) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_retention=0, post_retention=1)
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        mocker.patch.object(
            fake_elasticache,
            "describe_cache_clusters",
            return_value={"CacheClusters": [{"CacheClusterId": CLUSTER_ID}]},
        )
        with pytest.raises(
            rollback.ElastiCacheResponseError, match="no integer SnapshotRetentionLimit"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_snapshot_resource_id_mismatch_raises(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # Snapshot captured for a different resource must not be applied to this one.
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID,
            pre_retention=0,
            post_retention=1,
            resource_id="arn:aws:elasticache:us-east-1:123456789012:cluster:other-cluster",
        )
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        with pytest.raises(
            rollback.SnapshotValidationError,
            match="does not match the target resource ARN",
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_replicationgroup_disabled_mode_restore_passes_snapshotting_cluster(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # Rollback restoring to retention > 0 on a cluster-mode-disabled RG must pass SnapshottingClusterId
        # (the rollback-path counterpart to test_replicationgroup_disabled_mode_passes_snapshotting_cluster).
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID,
            pre_retention=5,
            post_retention=1,
            resource_id=REPLICATION_GROUP_ARN,
        )
        fake_elasticache.add_replication_group(
            REPLICATION_GROUP_ID,
            1,
            cluster_mode="disabled",
            snapshotting_cluster_id="test-group-001",
        )
        result = rollback.execute_rollback(
            _make_rollback_event(
                resource_arn=REPLICATION_GROUP_ARN, snapshot_version_id=version_id
            ),
            None,
        )
        assert result["Status"] == "SUCCESS"
        assert (
            fake_elasticache.replication_groups[REPLICATION_GROUP_ID][
                "SnapshotRetentionLimit"
            ]
            == 5
        )
        assert fake_elasticache.modify_replication_group_calls == [
            {
                "ReplicationGroupId": REPLICATION_GROUP_ID,
                "SnapshotRetentionLimit": 5,
                "SnapshottingClusterId": "test-group-001",
            }
        ]

    @mock_aws
    def test_replicationgroup_disabled_mode_rollback_to_zero_omits_snapshotting_cluster(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # Rolling back to retention 0 (disabling backups) on a cluster-mode-disabled RG must NOT pass
        # SnapshottingClusterId — it is only required when enabling backups (retention > 0).
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID,
            pre_retention=0,
            post_retention=1,
            resource_id=REPLICATION_GROUP_ARN,
        )
        fake_elasticache.add_replication_group(
            REPLICATION_GROUP_ID, 1, cluster_mode="disabled"
        )
        result = rollback.execute_rollback(
            _make_rollback_event(
                resource_arn=REPLICATION_GROUP_ARN, snapshot_version_id=version_id
            ),
            None,
        )
        assert result["Status"] == "SUCCESS"
        assert (
            fake_elasticache.replication_groups[REPLICATION_GROUP_ID][
                "SnapshotRetentionLimit"
            ]
            == 0
        )
        assert fake_elasticache.modify_replication_group_calls == [
            {"ReplicationGroupId": REPLICATION_GROUP_ID, "SnapshotRetentionLimit": 0}
        ]

    @mock_aws
    def test_missing_snapshot_version_id_raises(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        _put_snapshot(EXECUTION_ID, pre_retention=0)
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        with pytest.raises(
            rollback.SnapshotValidationError,
            match="Missing required parameter: SnapshotVersionId",
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_snapshot_not_found(self, fake_elasticache: FakeElastiCache) -> None:
        _create_snapshot_bucket()
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        with pytest.raises(rollback.SnapshotNotFoundError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="missing", snapshot_version_id="no-such-version"
                ),
                None,
            )
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_idempotent_when_already_rolled_back(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # pre=0, post=1, cluster currently 0 (== pre) -> idempotent no-op, not drift.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_retention=0, post_retention=1)
        fake_elasticache.add_cluster(CLUSTER_ID, 0)
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_drift_abort_when_current_differs_from_post(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # pre=0, post=1, but cluster currently 5 (someone changed it) -> drift, untouched.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_retention=0, post_retention=1)
        fake_elasticache.add_cluster(CLUSTER_ID, 5)
        with pytest.raises(
            rollback.SnapshotValidationError,
            match="does not match the post-remediation state",
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_schema_version_mismatch(self, fake_elasticache: FakeElastiCache) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_retention=0, schema_version=999)
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        with pytest.raises(
            rollback.SnapshotValidationError, match="schema version mismatch"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_malformed_snapshot_missing_state(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=_snapshot_key(),
            Body=json.dumps(
                {
                    "schemaVersion": 1,
                    "resourceId": CLUSTER_ARN,
                    "preRemediationState": {},
                    "postRemediationState": {},
                }
            ),
            ContentType="application/json",
        )
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_corrupt_snapshot_raises_validation_error(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=_snapshot_key(),
            Body="not-json{{{",
            ContentType="application/json",
        )
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_cluster_not_found(self, fake_elasticache: FakeElastiCache) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_retention=0)
        # cluster not added to the fake
        with pytest.raises(rollback.ResourceNotFoundError, match="not found"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_elasticache.modify_cache_cluster_calls == []

    @mock_aws
    def test_missing_account_id_raises(self, fake_elasticache: FakeElastiCache) -> None:
        _create_snapshot_bucket()
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        event = {
            "ResourceARN": CLUSTER_ARN,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v",
        }
        with pytest.raises(ValueError, match="Missing required parameter: AccountId"):
            rollback.execute_rollback(event, None)
        assert fake_elasticache.modify_cache_cluster_calls == []


# ── handler dispatch ─────────────────────────────────────────────────────────


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        fake_elasticache.add_cluster(CLUSTER_ID, 0)
        result = rollback.handler(_make_capture_event(retention=1), None)
        assert result["snapshotStored"] == "true"
        assert result["Message"] == ""
        assert fake_elasticache.clusters[CLUSTER_ID] == 1

    @mock_aws
    def test_dispatches_to_execute_rollback(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_retention=0, post_retention=1)
        fake_elasticache.add_cluster(CLUSTER_ID, 1)
        event = {
            **_make_rollback_event(snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }
        result = rollback.handler(event, None)
        assert result["Status"] == "SUCCESS"
        assert result["snapshotStored"] == ""
        assert fake_elasticache.clusters[CLUSTER_ID] == 0
