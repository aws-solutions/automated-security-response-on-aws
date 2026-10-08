# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for RDS.7 — EnableRDSClusterDeletionProtection rollback script.

moto implements RDS describe_db_clusters/modify_db_cluster (including
DeletionProtection), so these tests use real moto-backed clients — no fake.
"""
from __future__ import annotations

import json

import boto3
import EnableRDSClusterDeletionProtection_rollback as rollback
import pytest
from botocore.config import Config
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "RDS.7"
DB_CLUSTER_ID = "test-cluster"
RDS_CLUSTER_ARN = "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster"
ACCOUNT_ID = "123456789012"


def _create_cluster(deletion_protection: bool = False) -> None:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    rds.create_db_cluster(
        DBClusterIdentifier=DB_CLUSTER_ID,
        Engine="aurora-postgresql",
        MasterUsername="admin",
        MasterUserPassword="Password123!",  # NOSONAR test-only fixture credential
        DeletionProtection=deletion_protection,
    )


def _create_snapshot_bucket() -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=SNAPSHOT_BUCKET)
    s3.put_bucket_versioning(
        Bucket=SNAPSHOT_BUCKET, VersioningConfiguration={"Status": "Enabled"}
    )


def _put_snapshot(
    execution_id: str, deletion_protection: bool, schema_version: int = 1
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = f"snapshots/{execution_id}/{CONTROL_ID}.json"
    snapshot_data = {
        "schemaVersion": schema_version,
        "resourceId": RDS_CLUSTER_ARN,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"DeletionProtection": deletion_protection},
        "postRemediationState": {"DeletionProtection": True},
    }
    response = s3.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=key,
        Body=json.dumps(snapshot_data),
        ContentType="application/json",
    )
    return response["VersionId"]


def _get_deletion_protection() -> bool:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    return bool(
        rds.describe_db_clusters(DBClusterIdentifier=DB_CLUSTER_ID)["DBClusters"][
            0
        ].get("DeletionProtection", False)
    )


def _make_capture_event(
    bucket: str = SNAPSHOT_BUCKET, execution_id: str = EXECUTION_ID
) -> dict[str, object]:
    return {
        "RDSClusterARN": RDS_CLUSTER_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
        "ApplyImmediately": True,
    }


def _make_rollback_event(
    execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, object]:
    return {
        "RDSClusterARN": RDS_CLUSTER_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": execution_id,
        "SnapshotVersionId": snapshot_version_id,
        "ApplyImmediately": True,
    }


def test_apply_immediately_string_false_parsed_as_false() -> None:
    # SSM passes InputPayload values as strings, so "false" must become False, not True.
    capture_event = rollback._validate_capture_event(
        {**_make_capture_event(), "ApplyImmediately": "false"}
    )
    assert capture_event["ApplyImmediately"] is False
    rollback_event = rollback._validate_rollback_event(
        {**_make_rollback_event(snapshot_version_id="v"), "ApplyImmediately": "false"}
    )
    assert rollback_event["ApplyImmediately"] is False


# ═══════════════════════════════════════════════════════════════
# capture_and_remediate
# ═══════════════════════════════════════════════════════════════


class TestCaptureAndRemediate:
    @mock_aws
    def test_successful_snapshot_and_remediation(self) -> None:
        # GIVEN a cluster with deletion protection disabled and a snapshot bucket
        _create_snapshot_bucket()
        _create_cluster(deletion_protection=False)

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(_make_capture_event(), None)

        # THEN the snapshot is stored and deletion protection is enabled
        assert result["snapshotStored"] == "true"
        assert "Disable deletion protection" in result["rollbackDescription"]
        assert _get_deletion_protection() is True
        assert result["snapshotVersionId"] != ""

        # AND the snapshot in S3 reflects the original disabled state
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snapshot["schemaVersion"] == 1
        assert snapshot["preRemediationState"]["DeletionProtection"] is False
        assert snapshot["postRemediationState"]["DeletionProtection"] is True
        assert snapshot["resourceId"] == RDS_CLUSTER_ARN

    @mock_aws
    def test_fail_open_when_bucket_missing(self) -> None:
        # GIVEN no snapshot bucket exists
        _create_cluster(deletion_protection=False)

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="nonexistent-bucket"), None
        )

        # THEN snapshot write fails but remediation still proceeds (fail-open)
        assert result["snapshotStored"] == "false"
        assert _get_deletion_protection() is True

    @mock_aws
    def test_fail_open_when_bucket_not_provided(self) -> None:
        # GIVEN empty bucket/execution config
        _create_cluster(deletion_protection=False)

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="", execution_id=""), None
        )

        # THEN snapshot is skipped but remediation still proceeds
        assert result["snapshotStored"] == "false"
        assert _get_deletion_protection() is True

    @mock_aws
    def test_unversioned_bucket_reports_not_stored(self) -> None:
        boto3.client("s3", config=BOTO_CONFIG).create_bucket(Bucket=SNAPSHOT_BUCKET)
        _create_cluster(deletion_protection=False)
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert _get_deletion_protection() is True

    @mock_aws
    def test_already_enabled_returns_no_op_description(self) -> None:
        # GIVEN a cluster that already has deletion protection enabled
        _create_snapshot_bucket()
        _create_cluster(deletion_protection=True)

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(_make_capture_event(), None)

        # THEN the rollback description indicates a no-op and protection stays enabled
        assert result["snapshotStored"] == "true"
        assert "already enabled" in result["rollbackDescription"]
        assert "no-op" in result["rollbackDescription"].lower()
        assert _get_deletion_protection() is True

    @mock_aws
    def test_missing_required_parameter_raises(self) -> None:
        # GIVEN an event missing the required RDSClusterARN
        _create_cluster(deletion_protection=False)
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN it raises a clear validation error at the boundary
        with pytest.raises(ValueError, match="RDSClusterARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_invalid_resource_arn_raises(self) -> None:
        # GIVEN an ARN that is not an RDS DB cluster ARN
        _create_cluster(deletion_protection=False)
        event = {
            "RDSClusterARN": "not-an-arn",
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN it raises at the boundary with a specific message
        with pytest.raises(ValueError, match="expected an RDS DB cluster ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_non_arn_with_cluster_marker_raises(self) -> None:
        # GIVEN a string that contains ":cluster:" but is not an arn: (must not slip past the boundary)
        _create_cluster(deletion_protection=False)
        event = {
            "RDSClusterARN": "foo:cluster:test-cluster",
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN the arn: prefix check rejects it
        with pytest.raises(ValueError, match="expected an RDS DB cluster ARN"):
            rollback.capture_and_remediate(event, None)


# ═══════════════════════════════════════════════════════════════
# execute_rollback
# ═══════════════════════════════════════════════════════════════


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore(self) -> None:
        # GIVEN a cluster in the post-remediation state (enabled) and a snapshot indicating it was originally disabled
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_cluster(deletion_protection=True)

        # WHEN execute_rollback is called
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )

        # THEN deletion protection is disabled and status is SUCCESS
        assert result["Status"] == "SUCCESS"
        assert "Successfully restored" in result["Message"]
        assert _get_deletion_protection() is False

    @mock_aws
    def test_missing_snapshot_version_id_raises(self) -> None:
        # GIVEN a valid snapshot but no version id supplied (tamper-proof read impossible)
        _create_snapshot_bucket()
        _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_cluster(deletion_protection=True)

        # WHEN execute_rollback is called without a SnapshotVersionId THEN it aborts before touching the cluster
        with pytest.raises(RuntimeError, match="no snapshot version ID recorded"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        # GIVEN a snapshot bucket exists but has no snapshot for this execution
        _create_snapshot_bucket()
        _create_cluster(deletion_protection=True)

        # WHEN execute_rollback is called THEN it raises and the cluster is untouched
        with pytest.raises(RuntimeError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="missing-exec", snapshot_version_id="no-such-version"
                ),
                None,
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_snapshot_resource_id_mismatch_raises(self) -> None:
        # GIVEN a snapshot whose resourceId is a different cluster than the one being rolled back
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot_data = {
            "schemaVersion": 1,
            "resourceId": "arn:aws:rds:us-east-1:123456789012:cluster:other-cluster",
            "controlId": CONTROL_ID,
            "capturedAt": "2025-01-01T00:00:00+00:00",
            "preRemediationState": {"DeletionProtection": False},
            "postRemediationState": {"DeletionProtection": True},
        }
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(snapshot_data),
            ContentType="application/json",
        )
        _create_cluster(deletion_protection=True)

        # WHEN execute_rollback is called THEN it aborts because the snapshot is for a different resource
        with pytest.raises(RuntimeError, match="does not match the target cluster ARN"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_drift_detected_when_state_changed_after_remediation(self) -> None:
        # GIVEN a snapshot (pre=disabled, post=enabled) but the cluster is now disabled again —
        # i.e. the resource was modified after the ASR remediation
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_cluster(deletion_protection=False)

        # WHEN execute_rollback is called THEN it aborts with a drift error and does not modify the cluster
        with pytest.raises(RuntimeError, match="modified after the ASR remediation"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_deletion_protection() is False

    @mock_aws
    def test_no_op_when_pre_equals_post(self) -> None:
        # GIVEN a snapshot where deletion protection was already enabled before remediation
        # (pre == post == enabled) and the cluster is still enabled (no drift)
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=True)
        _create_cluster(deletion_protection=True)

        # WHEN execute_rollback is called THEN it is a no-op success and protection stays enabled
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_deletion_protection() is True

    @mock_aws
    def test_schema_version_mismatch(self) -> None:
        # GIVEN a snapshot written under an incompatible schema version
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, deletion_protection=False, schema_version=999
        )
        _create_cluster(deletion_protection=True)

        # WHEN execute_rollback is called THEN it raises and does not modify the cluster
        with pytest.raises(RuntimeError, match="schema version mismatch"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_cluster_not_found(self) -> None:
        # GIVEN a valid snapshot but the cluster no longer exists
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)

        # WHEN execute_rollback is called THEN the not-found error is normalized to a clear failure
        with pytest.raises(RuntimeError, match="not found"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_malformed_snapshot_missing_state(self) -> None:
        # GIVEN a snapshot whose state objects are present but lack the boolean DeletionProtection
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(
                {
                    "schemaVersion": 1,
                    "resourceId": RDS_CLUSTER_ARN,
                    "preRemediationState": {},
                    "postRemediationState": {},
                }
            ),
            ContentType="application/json",
        )
        _create_cluster(deletion_protection=True)

        # WHEN execute_rollback is called THEN it raises rather than performing a wrong rollback
        with pytest.raises(RuntimeError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_corrupt_snapshot_raises_read_error(self) -> None:
        # GIVEN a snapshot object whose body is not valid JSON
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body="not-json{{{",
            ContentType="application/json",
        )
        _create_cluster(deletion_protection=True)

        # WHEN execute_rollback is called THEN the read failure surfaces as a RollbackError, not a raw error
        with pytest.raises(RuntimeError, match="Failed to read snapshot"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_deletion_protection() is True


# ═══════════════════════════════════════════════════════════════
# handler (single dispatch entry point)
# ═══════════════════════════════════════════════════════════════


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(self) -> None:
        # GIVEN no Rollback flag (default remediation path)
        _create_snapshot_bucket()
        _create_cluster(deletion_protection=False)

        # WHEN handler is invoked
        result = rollback.handler(_make_capture_event(), None)

        # THEN it ran capture-and-remediate and returns a unified payload (rollback keys empty)
        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert _get_deletion_protection() is True

    @mock_aws
    def test_dispatches_to_execute_rollback(self) -> None:
        # GIVEN Rollback=ROLLBACK with a snapshot (pre=disabled, post=enabled) and the cluster currently enabled
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_cluster(deletion_protection=True)
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
        assert _get_deletion_protection() is False


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
            resource_arn=RDS_CLUSTER_ARN,
            was_deletion_protection_enabled=False,
        )

        # THEN it returns (True, non-empty version id) and the snapshot records pre/post state
        assert is_stored is True
        assert version_id != ""
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snapshot["preRemediationState"]["DeletionProtection"] is False
        assert snapshot["postRemediationState"]["DeletionProtection"] is True

    @mock_aws
    def test_skips_when_bucket_or_execution_id_empty(self) -> None:
        # GIVEN an empty bucket (e.g. the ENABLE_ROLLBACK gate cleared it)
        # WHEN _capture_snapshot is called THEN it skips the write and returns (False, "")
        assert rollback._capture_snapshot(
            "",
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            resource_arn=RDS_CLUSTER_ARN,
            was_deletion_protection_enabled=False,
        ) == (False, "")
        assert rollback._capture_snapshot(
            SNAPSHOT_BUCKET,
            execution_id="",
            account_id=ACCOUNT_ID,
            resource_arn=RDS_CLUSTER_ARN,
            was_deletion_protection_enabled=False,
        ) == (False, "")

    @mock_aws
    def test_fail_open_when_write_errors(self) -> None:
        # GIVEN a bucket that does not exist
        # WHEN _capture_snapshot is called THEN the write fails open, returning (False, "")
        is_stored, version_id = rollback._capture_snapshot(
            "nonexistent-bucket",
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            resource_arn=RDS_CLUSTER_ARN,
            was_deletion_protection_enabled=False,
        )
        assert is_stored is False
        assert version_id == ""
