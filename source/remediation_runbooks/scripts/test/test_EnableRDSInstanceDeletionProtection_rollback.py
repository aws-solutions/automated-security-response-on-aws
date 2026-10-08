# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for RDS.8 — EnableRDSInstanceDeletionProtection rollback script.

moto implements RDS describe_db_instances/modify_db_instance (including
DeletionProtection), so these tests use real moto-backed clients — no fake.
"""
from __future__ import annotations

import json

import boto3
import EnableRDSInstanceDeletionProtection_rollback as rollback
import pytest
from botocore.config import Config
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "RDS.8"
DB_INSTANCE_ID = "test-instance"
RDS_INSTANCE_ARN = "arn:aws:rds:us-east-1:123456789012:db:test-instance"
ACCOUNT_ID = "123456789012"


def _create_instance(deletion_protection: bool = False) -> None:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    rds.create_db_instance(
        DBInstanceIdentifier=DB_INSTANCE_ID,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        AllocatedStorage=20,
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
        "resourceId": RDS_INSTANCE_ARN,
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
        rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)["DBInstances"][
            0
        ].get("DeletionProtection", False)
    )


def _make_capture_event(
    bucket: str = SNAPSHOT_BUCKET, execution_id: str = EXECUTION_ID
) -> dict[str, object]:
    return {
        "RDSInstanceARN": RDS_INSTANCE_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
        "ApplyImmediately": True,
    }


def _make_rollback_event(
    execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, object]:
    return {
        "RDSInstanceARN": RDS_INSTANCE_ARN,
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
        # GIVEN an instance with deletion protection disabled and a snapshot bucket
        _create_snapshot_bucket()
        _create_instance(deletion_protection=False)

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
        assert snapshot["resourceId"] == RDS_INSTANCE_ARN

    @mock_aws
    def test_fail_open_when_bucket_missing(self) -> None:
        # GIVEN no snapshot bucket exists
        _create_instance(deletion_protection=False)

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
        _create_instance(deletion_protection=False)

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="", execution_id=""), None
        )

        # THEN snapshot is skipped but remediation still proceeds
        assert result["snapshotStored"] == "false"
        assert _get_deletion_protection() is True

    @mock_aws
    def test_already_enabled_returns_no_op_description(self) -> None:
        # GIVEN an instance that already has deletion protection enabled
        _create_snapshot_bucket()
        _create_instance(deletion_protection=True)

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(_make_capture_event(), None)

        # THEN the rollback description indicates a no-op and protection stays enabled
        assert result["snapshotStored"] == "true"
        assert "already enabled" in result["rollbackDescription"]
        assert "no-op" in result["rollbackDescription"].lower()
        assert _get_deletion_protection() is True

    @mock_aws
    def test_missing_required_parameter_raises(self) -> None:
        # GIVEN an event missing the required RDSInstanceARN
        _create_instance(deletion_protection=False)
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN it raises a clear validation error at the boundary
        with pytest.raises(ValueError, match="RDSInstanceARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_invalid_resource_arn_raises(self) -> None:
        # GIVEN an ARN that is not an RDS DB instance ARN
        _create_instance(deletion_protection=False)
        event = {
            "RDSInstanceARN": "not-an-arn",
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN it raises at the boundary with a specific message
        with pytest.raises(ValueError, match="expected an RDS DB instance ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_non_arn_with_db_marker_raises(self) -> None:
        # GIVEN a string that contains ":db:" but is not an arn: (must not slip past the boundary)
        _create_instance(deletion_protection=False)
        event = {
            "RDSInstanceARN": "foo:db:test-instance",
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }

        # WHEN capture_and_remediate is called THEN the arn: prefix check rejects it
        with pytest.raises(ValueError, match="expected an RDS DB instance ARN"):
            rollback.capture_and_remediate(event, None)


# ═══════════════════════════════════════════════════════════════
# execute_rollback
# ═══════════════════════════════════════════════════════════════


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore(self) -> None:
        # GIVEN an instance in the post-remediation state (enabled) and a snapshot indicating it was originally disabled
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_instance(deletion_protection=True)

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
        _create_instance(deletion_protection=True)

        # WHEN execute_rollback is called without a SnapshotVersionId THEN it aborts before touching the instance
        with pytest.raises(RuntimeError, match="no snapshot version ID recorded"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        # GIVEN a snapshot bucket exists but has no snapshot for this execution
        _create_snapshot_bucket()
        _create_instance(deletion_protection=True)

        # WHEN execute_rollback is called THEN it raises and the instance is untouched
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
        # GIVEN a snapshot (pre=disabled, post=enabled) but the instance is now disabled again —
        # i.e. the resource was modified after the ASR remediation
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_instance(deletion_protection=False)

        # WHEN execute_rollback is called THEN it aborts with a drift error and does not modify the instance
        with pytest.raises(RuntimeError, match="modified after the ASR remediation"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_deletion_protection() is False

    @mock_aws
    def test_no_op_when_pre_equals_post(self) -> None:
        # GIVEN a snapshot where deletion protection was already enabled before remediation
        # (pre == post == enabled) and the instance is still enabled (no drift)
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=True)
        _create_instance(deletion_protection=True)

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
        _create_instance(deletion_protection=True)

        # WHEN execute_rollback is called THEN it raises and does not modify the instance
        with pytest.raises(RuntimeError, match="schema version mismatch"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_deletion_protection() is True

    @mock_aws
    def test_instance_not_found(self) -> None:
        # GIVEN a valid snapshot but the instance no longer exists
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
                    "preRemediationState": {},
                    "postRemediationState": {},
                }
            ),
            ContentType="application/json",
        )
        _create_instance(deletion_protection=True)

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
        _create_instance(deletion_protection=True)

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
        _create_instance(deletion_protection=False)

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
        # GIVEN Rollback=ROLLBACK with a snapshot (pre=disabled, post=enabled) and the instance currently enabled
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, deletion_protection=False)
        _create_instance(deletion_protection=True)
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
            resource_arn=RDS_INSTANCE_ARN,
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
            resource_arn=RDS_INSTANCE_ARN,
            was_deletion_protection_enabled=False,
        ) == (False, "")
        assert rollback._capture_snapshot(
            SNAPSHOT_BUCKET,
            execution_id="",
            account_id=ACCOUNT_ID,
            resource_arn=RDS_INSTANCE_ARN,
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
            resource_arn=RDS_INSTANCE_ARN,
            was_deletion_protection_enabled=False,
        )
        assert is_stored is False
        assert version_id == ""

    @mock_aws
    def test_capture_asserts_bucket_ownership(self, mocker) -> None:
        # write_snapshot must pass ExpectedBucketOwner = AccountId so a config bucket sniped or
        # re-created in another account cannot be written to (CWE-283). moto ignores the header,
        # so spy on the real S3 client to assert the put carries it.
        _create_snapshot_bucket()
        real_client = boto3.client("s3", config=BOTO_CONFIG)
        put_spy = mocker.spy(real_client, "put_object")
        mocker.patch("common.snapshot_utils.boto3.client", return_value=real_client)

        rollback._capture_snapshot(
            SNAPSHOT_BUCKET,
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            resource_arn=RDS_INSTANCE_ARN,
            was_deletion_protection_enabled=False,
        )

        assert put_spy.call_args.kwargs["ExpectedBucketOwner"] == ACCOUNT_ID
