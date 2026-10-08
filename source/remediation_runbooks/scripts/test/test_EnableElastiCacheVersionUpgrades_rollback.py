# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for ElastiCache.2 — EnableElastiCacheVersionUpgrades rollback script.

moto 5.x does not implement elasticache:ModifyCacheCluster, so ElastiCache is served
by an in-memory FakeElastiCache routed through boto3.client; S3 still uses moto.
"""
from __future__ import annotations

import json
from typing import Any

import boto3
import EnableElastiCacheVersionUpgrades_rollback as rollback
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from moto import mock_aws
from pytest_mock import MockerFixture

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "ElastiCache.2"
CLUSTER_ID = "test-cluster"
ACCOUNT_ID = "123456789012"


class FakeElastiCache:
    """In-memory ElastiCache stand-in (moto doesn't implement modify_cache_cluster)."""

    def __init__(
        self,
        is_auto_upgrade_enabled: bool = False,
        does_exist: bool = True,
        should_raise_on_modify: bool = False,
    ) -> None:
        self.is_auto_upgrade_enabled = is_auto_upgrade_enabled
        self.does_exist = does_exist
        self.should_raise_on_modify = should_raise_on_modify
        self.modify_calls: list[bool] = []

    def describe_cache_clusters(
        self, *, CacheClusterId: str
    ) -> dict[str, Any]:  # noqa: N803 boto3 API kwarg
        if not self.does_exist:
            raise ClientError(
                {
                    "Error": {
                        "Code": "CacheClusterNotFound",
                        "Message": f"Cache cluster {CacheClusterId} not found",
                    }
                },
                "DescribeCacheClusters",
            )
        return {
            "CacheClusters": [
                {
                    "CacheClusterId": CacheClusterId,
                    "AutoMinorVersionUpgrade": self.is_auto_upgrade_enabled,
                }
            ]
        }

    def modify_cache_cluster(
        self, *, CacheClusterId: str, AutoMinorVersionUpgrade: bool
    ) -> dict[str, Any]:  # noqa: N803 boto3 API kwarg
        if self.should_raise_on_modify:
            raise ClientError(
                {
                    "Error": {
                        "Code": "InvalidCacheClusterState",
                        "Message": "modify failed",
                    }
                },
                "ModifyCacheCluster",
            )
        self.modify_calls.append(AutoMinorVersionUpgrade)
        self.is_auto_upgrade_enabled = AutoMinorVersionUpgrade
        return {
            "CacheCluster": {
                "CacheClusterId": CacheClusterId,
                "AutoMinorVersionUpgrade": AutoMinorVersionUpgrade,
            }
        }


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
    execution_id: str, is_auto_upgrade_enabled: bool, schema_version: int = 1
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = _snapshot_key(execution_id)
    snapshot_data = {
        "schemaVersion": schema_version,
        "resourceId": CLUSTER_ID,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"AutoMinorVersionUpgrade": is_auto_upgrade_enabled},
        "postRemediationState": {"AutoMinorVersionUpgrade": True},
    }
    response = s3.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=key,
        Body=json.dumps(snapshot_data),
        ContentType="application/json",
    )
    return response["VersionId"]


def _make_capture_event(
    *, bucket: str = SNAPSHOT_BUCKET, execution_id: str = EXECUTION_ID
) -> dict[str, object]:
    return {
        "ClusterId": CLUSTER_ID,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
    }


def _make_rollback_event(
    *, execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, object]:
    return {
        "ClusterId": CLUSTER_ID,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": execution_id,
        "SnapshotVersionId": snapshot_version_id,
    }


# ═══════════════════════════════════════════════════════════════
# capture_and_remediate
# ═══════════════════════════════════════════════════════════════


class TestCaptureAndRemediate:
    @mock_aws
    def test_successful_snapshot_and_remediation(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN a cluster with auto minor version upgrades disabled and a snapshot bucket
        _create_snapshot_bucket()
        fake_elasticache.is_auto_upgrade_enabled = False

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(_make_capture_event(), None)

        # THEN the snapshot is stored and auto upgrades are enabled
        assert result["snapshotStored"] == "true"
        assert (
            "Disable automatic minor version upgrades" in result["rollbackDescription"]
        )
        assert fake_elasticache.is_auto_upgrade_enabled is True
        assert fake_elasticache.modify_calls == [True]
        assert result["snapshotVersionId"] != ""

        # AND the snapshot in S3 reflects the original disabled state
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot = json.loads(
            s3.get_object(Bucket=SNAPSHOT_BUCKET, Key=_snapshot_key())["Body"].read()
        )
        assert snapshot["schemaVersion"] == 1
        assert snapshot["preRemediationState"]["AutoMinorVersionUpgrade"] is False
        assert snapshot["postRemediationState"]["AutoMinorVersionUpgrade"] is True
        assert snapshot["resourceId"] == CLUSTER_ID

    @mock_aws
    def test_fail_open_when_bucket_missing(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN no snapshot bucket exists
        fake_elasticache.is_auto_upgrade_enabled = False

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="nonexistent-bucket"), None
        )

        # THEN snapshot write fails but remediation still proceeds (fail-open)
        assert result["snapshotStored"] == "false"
        assert fake_elasticache.is_auto_upgrade_enabled is True

    @mock_aws
    def test_fail_open_when_bucket_not_provided(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN empty bucket/execution config
        fake_elasticache.is_auto_upgrade_enabled = False

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="", execution_id=""), None
        )

        # THEN snapshot is skipped but remediation still proceeds
        assert result["snapshotStored"] == "false"
        assert fake_elasticache.is_auto_upgrade_enabled is True

    @mock_aws
    def test_already_enabled_returns_no_op_description(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN a cluster that already has auto minor version upgrades enabled
        _create_snapshot_bucket()
        fake_elasticache.is_auto_upgrade_enabled = True

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(_make_capture_event(), None)

        # THEN the rollback description indicates a no-op and no modify was issued
        assert result["snapshotStored"] == "true"
        assert "already enabled" in result["rollbackDescription"]
        assert "no-op" in result["rollbackDescription"].lower()
        assert fake_elasticache.modify_calls == []

    @mock_aws
    def test_missing_cluster_id_raises(self, fake_elasticache: FakeElastiCache) -> None:
        # GIVEN an event missing the required ClusterId
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN it raises a clear validation error at the boundary
        with pytest.raises(ValueError, match="ClusterId"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_missing_account_id_raises(self, fake_elasticache: FakeElastiCache) -> None:
        # GIVEN an event missing the required AccountId (drops the S3 ExpectedBucketOwner assertion, CWE-283)
        event = {
            "ClusterId": CLUSTER_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN it raises at the boundary
        with pytest.raises(ValueError, match="AccountId"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_modify_failure_propagates_after_snapshot(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # If ModifyCacheCluster fails, the snapshot is already written but the exception must propagate
        # so the SSM step fails and the orchestrator never marks the execution rollbackAvailable.
        _create_snapshot_bucket()
        fake_elasticache.is_auto_upgrade_enabled = False
        fake_elasticache.should_raise_on_modify = True

        with pytest.raises(ClientError):
            rollback.capture_and_remediate(_make_capture_event(), None)

        # AND the pre-remediation snapshot was still written before the failed modify
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot = json.loads(
            s3.get_object(Bucket=SNAPSHOT_BUCKET, Key=_snapshot_key())["Body"].read()
        )
        assert snapshot["preRemediationState"]["AutoMinorVersionUpgrade"] is False


# ═══════════════════════════════════════════════════════════════
# execute_rollback
# ═══════════════════════════════════════════════════════════════


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore(self, fake_elasticache: FakeElastiCache) -> None:
        # GIVEN a cluster in the post-remediation state (enabled) and a snapshot indicating it was originally disabled
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, is_auto_upgrade_enabled=False)
        fake_elasticache.is_auto_upgrade_enabled = True

        # WHEN execute_rollback is called
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )

        # THEN auto upgrades are disabled and status is SUCCESS
        assert result["Status"] == "SUCCESS"
        assert "Successfully restored" in result["Message"]
        assert fake_elasticache.is_auto_upgrade_enabled is False
        assert fake_elasticache.modify_calls == [False]

    @mock_aws
    def test_missing_snapshot_version_id_raises(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN a valid snapshot but no version id supplied (tamper-proof read impossible)
        _create_snapshot_bucket()
        _put_snapshot(EXECUTION_ID, is_auto_upgrade_enabled=False)
        fake_elasticache.is_auto_upgrade_enabled = True

        # WHEN execute_rollback is called without a SnapshotVersionId THEN it aborts before touching the cluster
        with pytest.raises(RuntimeError, match="no snapshot version ID recorded"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert fake_elasticache.modify_calls == []

    @mock_aws
    def test_snapshot_not_found(self, fake_elasticache: FakeElastiCache) -> None:
        # GIVEN a snapshot bucket exists but has no snapshot for this execution
        _create_snapshot_bucket()
        fake_elasticache.is_auto_upgrade_enabled = True

        # WHEN execute_rollback is called THEN it raises and the cluster is untouched
        with pytest.raises(RuntimeError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="missing-exec", snapshot_version_id="no-such-version"
                ),
                None,
            )
        assert fake_elasticache.modify_calls == []

    @mock_aws
    def test_drift_detected_when_state_changed_after_remediation(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN a snapshot (pre=disabled, post=enabled) but the cluster is now disabled again —
        # i.e. the resource was modified after the ASR remediation
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, is_auto_upgrade_enabled=False)
        fake_elasticache.is_auto_upgrade_enabled = False

        # WHEN execute_rollback is called THEN it aborts with a drift error and does not modify the cluster
        with pytest.raises(RuntimeError, match="modified after the ASR remediation"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_elasticache.modify_calls == []

    @mock_aws
    def test_no_op_when_pre_equals_post(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN a snapshot where upgrades were already enabled before remediation (pre == post == enabled)
        # and the cluster is still enabled (no drift)
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, is_auto_upgrade_enabled=True)
        fake_elasticache.is_auto_upgrade_enabled = True

        # WHEN execute_rollback is called THEN it is a no-op success and no modify is issued
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert fake_elasticache.modify_calls == []

    @mock_aws
    def test_schema_version_mismatch(self, fake_elasticache: FakeElastiCache) -> None:
        # GIVEN a snapshot written under an incompatible schema version
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, is_auto_upgrade_enabled=False, schema_version=999
        )
        fake_elasticache.is_auto_upgrade_enabled = True

        # WHEN execute_rollback is called THEN it raises and does not modify the cluster
        with pytest.raises(RuntimeError, match="schema version mismatch"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_elasticache.modify_calls == []

    @mock_aws
    def test_cluster_not_found(self, fake_elasticache: FakeElastiCache) -> None:
        # GIVEN a valid snapshot but the cluster no longer exists
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, is_auto_upgrade_enabled=False)
        fake_elasticache.does_exist = False

        # WHEN execute_rollback is called THEN the not-found error is normalized to a clear failure
        with pytest.raises(RuntimeError, match="not found"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_elasticache.modify_calls == []

    @mock_aws
    def test_malformed_snapshot_missing_state(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN a snapshot whose state objects are present but lack the boolean AutoMinorVersionUpgrade
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=_snapshot_key(),
            Body=json.dumps(
                {
                    "schemaVersion": 1,
                    "preRemediationState": {},
                    "postRemediationState": {},
                }
            ),
            ContentType="application/json",
        )
        fake_elasticache.is_auto_upgrade_enabled = True

        # WHEN execute_rollback is called THEN it raises rather than performing a wrong rollback
        with pytest.raises(RuntimeError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert fake_elasticache.modify_calls == []

    @mock_aws
    def test_corrupt_snapshot_raises_read_error(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN a snapshot object whose body is not valid JSON
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=_snapshot_key(),
            Body="not-json{{{",
            ContentType="application/json",
        )
        fake_elasticache.is_auto_upgrade_enabled = True

        # WHEN execute_rollback is called THEN the read failure surfaces as a RollbackError, not a raw error
        with pytest.raises(RuntimeError, match="Failed to read snapshot"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert fake_elasticache.modify_calls == []


# ═══════════════════════════════════════════════════════════════
# handler (single dispatch entry point)
# ═══════════════════════════════════════════════════════════════


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN no Rollback flag (default remediation path)
        _create_snapshot_bucket()
        fake_elasticache.is_auto_upgrade_enabled = False

        # WHEN handler is invoked
        result = rollback.handler(_make_capture_event(), None)

        # THEN it ran capture-and-remediate and returns a unified payload (rollback keys empty)
        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert fake_elasticache.is_auto_upgrade_enabled is True

    @mock_aws
    def test_dispatches_to_execute_rollback(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # GIVEN Rollback=ROLLBACK with a snapshot (pre=disabled, post=enabled) and the cluster currently enabled
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, is_auto_upgrade_enabled=False)
        fake_elasticache.is_auto_upgrade_enabled = True
        event = {
            **_make_rollback_event(snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }

        # WHEN handler is invoked
        result = rollback.handler(event, None)

        # THEN it ran rollback and returns a unified payload (capture keys empty)
        assert result["Status"] == "SUCCESS"
        assert "Successfully restored" in result["Message"]
        assert result["snapshotStored"] == ""
        assert fake_elasticache.is_auto_upgrade_enabled is False

    @mock_aws
    def test_invalid_rollback_value_raises(
        self, fake_elasticache: FakeElastiCache
    ) -> None:
        # An unrecognized non-empty Rollback value is rejected at the boundary rather than silently remediating.
        with pytest.raises(ValueError, match="Invalid Rollback parameter"):
            rollback.handler({**_make_capture_event(), "Rollback": "ROLBACK"}, None)
        assert fake_elasticache.modify_calls == []


# ═══════════════════════════════════════════════════════════════
# _capture_snapshot (extracted helper)
# ═══════════════════════════════════════════════════════════════


class TestCaptureSnapshot:
    @mock_aws
    def test_stores_and_returns_version(self) -> None:
        # GIVEN a snapshot bucket
        _create_snapshot_bucket()

        # WHEN _capture_snapshot is called with a valid bucket + execution id
        is_stored, version_id = rollback._capture_snapshot(
            SNAPSHOT_BUCKET,
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            cluster_id=CLUSTER_ID,
            was_auto_upgrade_enabled=False,
        )

        # THEN it returns (True, non-empty version id) and the snapshot records pre/post state
        assert is_stored is True
        assert version_id != ""
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot = json.loads(
            s3.get_object(Bucket=SNAPSHOT_BUCKET, Key=_snapshot_key())["Body"].read()
        )
        assert snapshot["preRemediationState"]["AutoMinorVersionUpgrade"] is False
        assert snapshot["postRemediationState"]["AutoMinorVersionUpgrade"] is True

    @mock_aws
    def test_skips_when_bucket_or_execution_id_empty(self) -> None:
        # GIVEN an empty bucket (e.g. the ENABLE_ROLLBACK gate cleared it)
        # WHEN _capture_snapshot is called THEN it skips the write and returns (False, "")
        assert rollback._capture_snapshot(
            "",
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            cluster_id=CLUSTER_ID,
            was_auto_upgrade_enabled=False,
        ) == (False, "")
        assert rollback._capture_snapshot(
            SNAPSHOT_BUCKET,
            execution_id="",
            account_id=ACCOUNT_ID,
            cluster_id=CLUSTER_ID,
            was_auto_upgrade_enabled=False,
        ) == (False, "")

    @mock_aws
    def test_fail_open_when_write_errors(self) -> None:
        # GIVEN a bucket that does not exist
        # WHEN _capture_snapshot is called THEN the write fails open, returning (False, "")
        is_stored, version_id = rollback._capture_snapshot(
            "nonexistent-bucket",
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            cluster_id=CLUSTER_ID,
            was_auto_upgrade_enabled=False,
        )
        assert is_stored is False
        assert version_id == ""
