# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for DynamoDB.6 — EnableDynamoDBDeletionProtection rollback script.

moto fully implements DynamoDB describe_table/update_table (including
DeletionProtectionEnabled), so these tests use real moto-backed clients — no fake.
"""
from __future__ import annotations

import json

import boto3
import EnableDynamoDBDeletionProtection_rollback as rollback
import pytest
from botocore.config import Config
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "DynamoDB.6"
TABLE_NAME = "test-table"
TABLE_ARN = "arn:aws:dynamodb:us-east-1:123456789012:table/test-table"
ACCOUNT_ID = "123456789012"


def _create_table(deletion_protection: bool = False) -> None:
    dynamodb = boto3.client("dynamodb", config=BOTO_CONFIG)
    dynamodb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        DeletionProtectionEnabled=deletion_protection,
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
        "resourceId": TABLE_ARN,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"DeletionProtectionEnabled": deletion_protection},
        "postRemediationState": {"DeletionProtectionEnabled": True},
    }
    response = s3.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=key,
        Body=json.dumps(snapshot_data),
        ContentType="application/json",
    )
    return response["VersionId"]


def _get_deletion_protection() -> bool:
    dynamodb = boto3.client("dynamodb", config=BOTO_CONFIG)
    return bool(
        dynamodb.describe_table(TableName=TABLE_NAME)["Table"].get(
            "DeletionProtectionEnabled", False
        )
    )


def _make_capture_event(
    bucket: str = SNAPSHOT_BUCKET, execution_id: str = EXECUTION_ID
) -> dict[str, str]:
    return {
        "ResourceArn": TABLE_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
    }


def _make_rollback_event(
    execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, str]:
    return {
        "ResourceArn": TABLE_ARN,
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
    def test_successful_snapshot_and_remediation(self) -> None:
        # GIVEN a table with deletion protection disabled and a snapshot bucket
        _create_snapshot_bucket()
        _create_table(deletion_protection=False)

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
        assert snapshot["preRemediationState"]["DeletionProtectionEnabled"] is False
        assert snapshot["postRemediationState"]["DeletionProtectionEnabled"] is True
        assert snapshot["resourceId"] == TABLE_ARN

    @mock_aws
    def test_fail_open_when_bucket_missing(self) -> None:
        # GIVEN no snapshot bucket exists
        _create_table(deletion_protection=False)

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
        _create_table(deletion_protection=False)

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="", execution_id=""), None
        )

        # THEN snapshot is skipped but remediation still proceeds
        assert result["snapshotStored"] == "false"
        assert _get_deletion_protection() is True

    @mock_aws
    def test_already_enabled_returns_no_op_description(self) -> None:
        # GIVEN a table that already has deletion protection enabled
        _create_snapshot_bucket()
        _create_table(deletion_protection=True)

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(_make_capture_event(), None)

        # THEN the rollback description indicates a no-op and protection stays enabled
        assert result["snapshotStored"] == "true"
        assert "already enabled" in result["rollbackDescription"]
        assert "no-op" in result["rollbackDescription"].lower()
        assert _get_deletion_protection() is True

    @mock_aws
    def test_missing_required_parameter_raises(self) -> None:
        # GIVEN an event missing the required ResourceArn
        _create_table(deletion_protection=False)
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN it raises a clear validation error at the boundary
        with pytest.raises(ValueError, match="required parameter: ResourceArn"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_invalid_resource_arn_raises(self) -> None:
        # GIVEN a ResourceArn that is not a DynamoDB table ARN
        _create_table(deletion_protection=False)
        event = {
            "ResourceArn": "not-an-arn",
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN it raises at the boundary with a specific message
        with pytest.raises(ValueError, match="expected a DynamoDB table ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_non_arn_with_table_marker_raises(self) -> None:
        # GIVEN a string that contains ":table/" but is not an arn: (must not slip past the boundary)
        _create_table(deletion_protection=False)
        event = {
            "ResourceArn": "foo:table/test-table",
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN the arn: prefix check rejects it
        with pytest.raises(ValueError, match="expected a DynamoDB table ARN"):
            rollback.capture_and_remediate(event, None)


# ═══════════════════════════════════════════════════════════════
# execute_rollback
# ═══════════════════════════════════════════════════════════════


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore(self) -> None:
        # GIVEN a table in the post-remediation state (enabled) and a snapshot indicating it was originally disabled
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_table(deletion_protection=True)

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
        _create_table(deletion_protection=True)

        # WHEN execute_rollback is called without a SnapshotVersionId THEN it aborts before touching the table
        with pytest.raises(RuntimeError, match="no snapshot version ID recorded"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        # GIVEN a snapshot bucket exists but has no snapshot for this execution
        _create_snapshot_bucket()
        _create_table(deletion_protection=True)

        # WHEN execute_rollback is called THEN it raises and the table is untouched
        with pytest.raises(RuntimeError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="missing-exec", snapshot_version_id="no-such-version"
                ),
                None,
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_drift_detected_when_state_changed_after_remediation(self) -> None:
        # GIVEN a snapshot (pre=disabled, post=enabled) but the table is now disabled again —
        # i.e. the resource was modified after the ASR remediation
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_table(deletion_protection=False)

        # WHEN execute_rollback is called THEN it aborts with a drift error and does not modify the table
        with pytest.raises(RuntimeError, match="modified after the ASR remediation"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_deletion_protection() is False

    @mock_aws
    def test_no_op_when_pre_equals_post(self) -> None:
        # GIVEN a snapshot where deletion protection was already enabled before remediation
        # (pre == post == enabled) and the table is still enabled (no drift)
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=True)
        _create_table(deletion_protection=True)

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
        _create_table(deletion_protection=True)

        # WHEN execute_rollback is called THEN it raises and does not modify the table
        with pytest.raises(RuntimeError, match="schema version mismatch"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_table_not_found(self) -> None:
        # GIVEN a valid snapshot but the table no longer exists
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)

        # WHEN execute_rollback is called THEN the not-found error is normalized to a clear failure
        with pytest.raises(RuntimeError, match="not found"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_malformed_snapshot_missing_state(self) -> None:
        # GIVEN a snapshot whose state objects are present but lack the boolean DeletionProtectionEnabled
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
        _create_table(deletion_protection=True)

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
        _create_table(deletion_protection=True)

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
        _create_table(deletion_protection=False)

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
        # GIVEN Rollback=ROLLBACK with a snapshot (pre=disabled, post=enabled) and the table currently enabled
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_table(deletion_protection=True)
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
        stored, version_id = rollback._capture_snapshot(
            SNAPSHOT_BUCKET,
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            resource_arn=TABLE_ARN,
            was_deletion_protection_enabled=False,
        )

        # THEN it returns (True, non-empty version id) and the snapshot records pre/post state
        assert stored is True
        assert version_id != ""
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snap = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snap["preRemediationState"]["DeletionProtectionEnabled"] is False
        assert snap["postRemediationState"]["DeletionProtectionEnabled"] is True

    @mock_aws
    def test_skips_when_bucket_or_execution_id_empty(self) -> None:
        # GIVEN an empty bucket (e.g. the ENABLE_ROLLBACK gate cleared it)
        # WHEN _capture_snapshot is called THEN it skips the write and returns (False, "")
        assert rollback._capture_snapshot(
            "",
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            resource_arn=TABLE_ARN,
            was_deletion_protection_enabled=False,
        ) == (False, "")
        assert rollback._capture_snapshot(
            SNAPSHOT_BUCKET,
            execution_id="",
            account_id=ACCOUNT_ID,
            resource_arn=TABLE_ARN,
            was_deletion_protection_enabled=False,
        ) == (False, "")

    @mock_aws
    def test_fail_open_when_write_errors(self) -> None:
        # GIVEN a bucket that does not exist
        # WHEN _capture_snapshot is called THEN the write fails open, returning (False, "")
        stored, version_id = rollback._capture_snapshot(
            "nonexistent-bucket",
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            resource_arn=TABLE_ARN,
            was_deletion_protection_enabled=False,
        )
        assert stored is False
        assert version_id == ""
