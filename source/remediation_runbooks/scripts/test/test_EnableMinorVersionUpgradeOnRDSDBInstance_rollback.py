# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for RDS.13 — EnableMinorVersionUpgradeOnRDSDBInstance rollback script.

moto implements RDS describe/modify for instances, so these tests use real moto-backed clients. State
is AutoMinorVersionUpgrade (bool); the setting is applied on the Multi-AZ cluster the instance belongs
to (mysql/postgres) or on the instance itself.
"""
from __future__ import annotations

import json

import boto3
import EnableMinorVersionUpgradeOnRDSDBInstance_rollback as rollback
import pytest
from botocore.config import Config
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "RDS.13"
ACCOUNT_ID = "123456789012"
INSTANCE_ID = "asr-test-instance"
INSTANCE_ARN = "arn:aws:rds:us-east-1:123456789012:db:asr-test-instance"


def _create_instance(is_auto_minor_upgrade_enabled: bool = False) -> None:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    rds.create_db_instance(
        DBInstanceIdentifier=INSTANCE_ID,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        AllocatedStorage=20,
        MasterUsername="admin",
        MasterUserPassword="Password123!",  # NOSONAR test-only fixture credential
        AutoMinorVersionUpgrade=is_auto_minor_upgrade_enabled,
    )


def _get_instance_auto_minor() -> bool:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    return bool(
        rds.describe_db_instances(DBInstanceIdentifier=INSTANCE_ID)["DBInstances"][
            0
        ].get("AutoMinorVersionUpgrade", False)
    )


def _create_snapshot_bucket() -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=SNAPSHOT_BUCKET)
    s3.put_bucket_versioning(
        Bucket=SNAPSHOT_BUCKET, VersioningConfiguration={"Status": "Enabled"}
    )


def _put_snapshot(
    execution_id: str,
    *,
    is_pre_remediation_enabled: bool,
    is_post_remediation_enabled: bool = True,
    schema_version: int = 1,
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = f"snapshots/{execution_id}/{CONTROL_ID}.json"
    snapshot_data = {
        "schemaVersion": schema_version,
        "resourceId": INSTANCE_ARN,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"AutoMinorVersionUpgrade": is_pre_remediation_enabled},
        "postRemediationState": {
            "AutoMinorVersionUpgrade": is_post_remediation_enabled
        },
    }
    response = s3.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=key,
        Body=json.dumps(snapshot_data),
        ContentType="application/json",
    )
    return response["VersionId"]


def _make_capture_event(
    bucket: str = SNAPSHOT_BUCKET, execution_id: str = EXECUTION_ID
) -> dict[str, object]:
    return {
        "RDSInstanceARN": INSTANCE_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
    }


def _make_rollback_event(
    execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, object]:
    return {
        "RDSInstanceARN": INSTANCE_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": execution_id,
        "SnapshotVersionId": snapshot_version_id,
    }


# ── unit: ARN validation + target resolution ─────────────────────────────────


def test_validate_instance_arn_rejects_non_db_arn() -> None:
    with pytest.raises(ValueError, match="expected an RDS DB instance ARN"):
        rollback._validate_instance_arn(
            {"RDSInstanceARN": "arn:aws:rds:us-east-1:123456789012:cluster:c"},
            ACCOUNT_ID,
        )


def test_validate_instance_arn_rejects_cross_account() -> None:
    other = "arn:aws:rds:us-east-1:999999999999:db:asr-test-instance"
    with pytest.raises(ValueError, match="does not match the executing account"):
        rollback._validate_instance_arn({"RDSInstanceARN": other}, ACCOUNT_ID)


@mock_aws
def test_resolve_target_standalone_instance() -> None:
    _create_instance()
    rds = boto3.client("rds", config=BOTO_CONFIG)
    assert rollback._resolve_target(rds, INSTANCE_ID) == ("instance", INSTANCE_ID)


def test_is_multi_az_db_cluster() -> None:
    # Cluster target only when MultiAZ AND a mysql/postgres engine (Multi-AZ DB cluster, not Aurora).
    assert (
        rollback._is_multi_az_db_cluster({"MultiAZ": True, "Engine": "mysql"}) is True
    )
    assert (
        rollback._is_multi_az_db_cluster({"MultiAZ": True, "Engine": "postgres"})
        is True
    )
    assert (
        rollback._is_multi_az_db_cluster({"MultiAZ": False, "Engine": "mysql"}) is False
    )
    assert (
        rollback._is_multi_az_db_cluster({"MultiAZ": True, "Engine": "aurora-mysql"})
        is False
    )


CLUSTER_ID = "asr-test-cluster"


def _create_mysql_cluster() -> None:
    boto3.client("rds", config=BOTO_CONFIG).create_db_cluster(
        DBClusterIdentifier=CLUSTER_ID,
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Password123!",  # NOSONAR test-only fixture credential
        DBClusterInstanceClass="db.m6gd.large",
        AllocatedStorage=100,
        Iops=1000,
    )


@mock_aws
def test_cluster_target_read_and_modify() -> None:
    # Cover the cluster dispatch branches of _describe_one / _get_auto_minor_version_upgrade / _set_auto_minor_version_upgrade.
    # (moto can't set MultiAZ=True, so _resolve_target can't return a cluster naturally; exercise the
    # cluster target directly.)
    _create_mysql_cluster()
    rds = boto3.client("rds", config=BOTO_CONFIG)
    target = rollback.ModifyTarget("cluster", CLUSTER_ID)
    rollback._set_auto_minor_version_upgrade(rds, target, enabled=False)
    assert rollback._get_auto_minor_version_upgrade(rds, target) is False
    rollback._set_auto_minor_version_upgrade(rds, target, enabled=True)
    assert rollback._get_auto_minor_version_upgrade(rds, target) is True


@mock_aws
def test_cluster_not_found_raises() -> None:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    with pytest.raises(rollback.ResourceNotFoundError, match="not found"):
        rollback._get_auto_minor_version_upgrade(
            rds, rollback.ModifyTarget("cluster", "no-such-cluster")
        )


# ── capture_and_remediate (instance path) ────────────────────────────────────


class TestCaptureAndRemediate:
    @mock_aws
    def test_successful_snapshot_and_remediation(self) -> None:
        _create_snapshot_bucket()
        _create_instance(is_auto_minor_upgrade_enabled=False)
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        assert "Disable AutoMinorVersionUpgrade" in result["rollbackDescription"]
        assert result["snapshotVersionId"] != ""
        assert _get_instance_auto_minor() is True
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snap = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snap["preRemediationState"]["AutoMinorVersionUpgrade"] is False
        assert snap["postRemediationState"]["AutoMinorVersionUpgrade"] is True
        assert snap["resourceId"] == INSTANCE_ARN

    @mock_aws
    def test_no_op_when_already_enabled(self) -> None:
        _create_snapshot_bucket()
        _create_instance(is_auto_minor_upgrade_enabled=True)
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "No remediation needed" in result["rollbackDescription"]
        assert _get_instance_auto_minor() is True
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        objs = s3.list_objects_v2(
            Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
        )
        assert objs.get("KeyCount", 0) == 0

    @mock_aws
    def test_fail_open_when_bucket_missing(self) -> None:
        _create_instance(is_auto_minor_upgrade_enabled=False)
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="nonexistent-bucket"), None
        )
        assert result["snapshotStored"] == "false"
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert _get_instance_auto_minor() is True

    @mock_aws
    def test_non_string_bucket_treated_as_absent(self) -> None:
        _create_instance(is_auto_minor_upgrade_enabled=False)
        result = rollback.capture_and_remediate(
            {**_make_capture_event(), "RemediationConfigBucket": None}, None
        )
        assert result["snapshotStored"] == "false"
        assert _get_instance_auto_minor() is True

    @mock_aws
    def test_missing_instance_arn_raises(self) -> None:
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }
        with pytest.raises(ValueError, match="expected an RDS DB instance ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_cross_account_instance_rejected(self) -> None:
        event = {
            **_make_capture_event(),
            "RDSInstanceARN": "arn:aws:rds:us-east-1:999999999999:db:asr-test-instance",
        }
        with pytest.raises(ValueError, match="does not match the executing account"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_invalid_account_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="expected 12-digit AWS account ID"):
            rollback.capture_and_remediate(
                {**_make_capture_event(), "AccountId": "123"}, None
            )


# ── execute_rollback (instance path) ─────────────────────────────────────────


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, is_pre_remediation_enabled=False)
        _create_instance(
            is_auto_minor_upgrade_enabled=True
        )  # currently in post-remediation state
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "Successfully restored" in result["Message"]
        assert _get_instance_auto_minor() is False

    @mock_aws
    def test_missing_snapshot_version_id_raises(self) -> None:
        _create_snapshot_bucket()
        _put_snapshot(EXECUTION_ID, is_pre_remediation_enabled=False)
        _create_instance(is_auto_minor_upgrade_enabled=True)
        with pytest.raises(
            rollback.SnapshotValidationError,
            match="Missing required parameter: SnapshotVersionId",
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert _get_instance_auto_minor() is True

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        _create_snapshot_bucket()
        _create_instance(is_auto_minor_upgrade_enabled=True)
        with pytest.raises(rollback.SnapshotNotFoundError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="missing-exec", snapshot_version_id="no-such-version"
                ),
                None,
            )
        assert _get_instance_auto_minor() is True

    @mock_aws
    def test_idempotent_when_already_rolled_back(self) -> None:
        # pre=False, post=True, instance currently False (== pre) -> idempotent no-op SUCCESS, not drift.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, is_pre_remediation_enabled=False)
        _create_instance(is_auto_minor_upgrade_enabled=False)
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_instance_auto_minor() is False

    @mock_aws
    def test_drift_abort_when_current_differs_from_post(self) -> None:
        # pre == post == enabled, but instance currently disabled -> drift gate fires, instance untouched.
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID,
            is_pre_remediation_enabled=True,
            is_post_remediation_enabled=True,
        )
        _create_instance(is_auto_minor_upgrade_enabled=False)
        with pytest.raises(
            rollback.SnapshotValidationError,
            match="does not match the post-remediation state",
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_instance_auto_minor() is False

    @mock_aws
    def test_schema_version_mismatch(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, is_pre_remediation_enabled=False, schema_version=999
        )
        _create_instance(is_auto_minor_upgrade_enabled=True)
        with pytest.raises(
            rollback.SnapshotValidationError, match="schema version mismatch"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_instance_auto_minor() is True

    @mock_aws
    def test_malformed_snapshot_missing_state(self) -> None:
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(
                {
                    "schemaVersion": 1,
                    "preRemediationState": {},
                    "postRemediationState": {},
                }
            ),
            ContentType="application/json",
        )
        _create_instance(is_auto_minor_upgrade_enabled=True)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_instance_auto_minor() is True

    @mock_aws
    def test_corrupt_snapshot_raises_validation_error(self) -> None:
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body="not-json{{{",
            ContentType="application/json",
        )
        _create_instance(is_auto_minor_upgrade_enabled=True)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_instance_auto_minor() is True

    @mock_aws
    def test_instance_not_found(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, is_pre_remediation_enabled=False)
        with pytest.raises(rollback.ResourceNotFoundError, match="not found"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_missing_required_param_raises(self) -> None:
        _create_snapshot_bucket()
        _create_instance(is_auto_minor_upgrade_enabled=True)
        event = {
            "RDSInstanceARN": INSTANCE_ARN,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v",
        }
        with pytest.raises(ValueError, match="Missing required parameter: AccountId"):
            rollback.execute_rollback(event, None)
        assert _get_instance_auto_minor() is True


# ── handler dispatch ─────────────────────────────────────────────────────────


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(self) -> None:
        _create_snapshot_bucket()
        _create_instance(is_auto_minor_upgrade_enabled=False)
        result = rollback.handler(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert _get_instance_auto_minor() is True

    @mock_aws
    def test_dispatches_to_execute_rollback(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, is_pre_remediation_enabled=False)
        _create_instance(is_auto_minor_upgrade_enabled=True)
        event = {
            **_make_rollback_event(snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }
        result = rollback.handler(event, None)
        assert result["Status"] == "SUCCESS"
        assert result["snapshotStored"] == ""
        assert _get_instance_auto_minor() is False

    @mock_aws
    def test_non_string_rollback_flag_dispatches_to_capture(self) -> None:
        _create_snapshot_bucket()
        _create_instance(is_auto_minor_upgrade_enabled=False)
        result = rollback.handler({**_make_capture_event(), "Rollback": None}, None)
        assert result["snapshotStored"] == "true"
        assert _get_instance_auto_minor() is True
