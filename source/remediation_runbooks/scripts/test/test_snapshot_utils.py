# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for common/snapshot_utils.py — shared snapshot read/write utilities."""
from __future__ import annotations

import json

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from common.snapshot_utils import (
    CaptureResult,
    RollbackAction,
    RollbackResult,
    SnapshotValidationError,
    capture_snapshot,
    dispatch_rollback_handler,
    get_post_remediation_state,
    get_pre_remediation_state,
    read_snapshot,
    resolve_rollback_action,
    validate_common_rollback_fields,
    write_snapshot,
)
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
BUCKET = "test-snapshot-bucket"
EXECUTION_ID = "exec-test-123"
CONTROL_ID = "KMS.4"


def _create_bucket(versioned: bool = True) -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=BUCKET)
    if versioned:
        s3.put_bucket_versioning(
            Bucket=BUCKET,
            VersioningConfiguration={"Status": "Enabled"},
        )


class TestWriteSnapshot:
    @mock_aws
    def test_successful_write_returns_true_and_version_id(self) -> None:
        _create_bucket()
        data = {"schemaVersion": 1, "preRemediationState": {"foo": "bar"}}

        success, version_id = write_snapshot(
            BUCKET, execution_id=EXECUTION_ID, control_id=CONTROL_ID, data=data
        )

        assert success is True
        assert version_id is not None
        assert len(version_id) > 0

        # Verify object was actually written
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.get_object(
            Bucket=BUCKET, Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json"
        )
        stored = json.loads(response["Body"].read())
        assert stored == data

    @mock_aws
    def test_empty_bucket_returns_false_none(self) -> None:
        success, version_id = write_snapshot(
            "", execution_id=EXECUTION_ID, control_id=CONTROL_ID, data={"data": 1}
        )

        assert success is False
        assert version_id is None

    @mock_aws
    def test_empty_execution_id_returns_false_none(self) -> None:
        success, version_id = write_snapshot(
            BUCKET, execution_id="", control_id=CONTROL_ID, data={"data": 1}
        )

        assert success is False
        assert version_id is None

    @mock_aws
    def test_s3_error_returns_false_none_without_raising(self) -> None:
        # Bucket doesn't exist — PutObject will fail
        data = {"schemaVersion": 1}

        success, version_id = write_snapshot(
            "nonexistent-bucket",
            execution_id=EXECUTION_ID,
            control_id=CONTROL_ID,
            data=data,
        )

        assert success is False
        assert version_id is None

    @mock_aws
    def test_key_format_includes_control_id(self) -> None:
        _create_bucket()
        data = {"test": True}

        write_snapshot(BUCKET, execution_id="my-exec-id", control_id="S3.4", data=data)

        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.get_object(Bucket=BUCKET, Key="snapshots/my-exec-id/S3.4.json")
        assert json.loads(response["Body"].read()) == data


class TestReadSnapshot:
    @mock_aws
    def test_successful_read(self) -> None:
        _create_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        data = {"controlId": "KMS.4", "state": {"KeyRotationEnabled": False}}
        s3.put_object(
            Bucket=BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(data),
        )

        result = read_snapshot(BUCKET, execution_id=EXECUTION_ID, control_id=CONTROL_ID)

        assert result == data

    @mock_aws
    def test_read_with_version_id(self) -> None:
        _create_bucket(versioned=True)
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        key = f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json"

        # Write v1
        data_v1 = {"version": 1}
        resp_v1 = s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(data_v1))
        version_id_v1 = resp_v1["VersionId"]

        # Write v2 (overwrites)
        data_v2 = {"version": 2}
        s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(data_v2))

        # Read with version_id should get v1
        result = read_snapshot(
            BUCKET,
            execution_id=EXECUTION_ID,
            control_id=CONTROL_ID,
            version_id=version_id_v1,
        )
        assert result == data_v1

        # Read without version_id should get latest (v2)
        result_latest = read_snapshot(
            BUCKET, execution_id=EXECUTION_ID, control_id=CONTROL_ID
        )
        assert result_latest == data_v2

    @mock_aws
    def test_no_such_key_returns_none(self) -> None:
        _create_bucket()

        result = read_snapshot(
            BUCKET, execution_id="nonexistent-exec", control_id=CONTROL_ID
        )

        assert result is None

    @mock_aws
    def test_no_such_bucket_returns_none(self) -> None:
        result = read_snapshot(
            "bucket-does-not-exist", execution_id=EXECUTION_ID, control_id=CONTROL_ID
        )

        assert result is None

    @mock_aws
    def test_no_such_version_returns_none(self) -> None:
        _create_bucket(versioned=True)
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        s3.put_object(
            Bucket=BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps({"data": 1}),
        )

        # moto doesn't simulate NoSuchVersion for bogus version IDs.
        # Mock the S3 client to raise the expected ClientError.
        from unittest.mock import MagicMock, patch

        mock_s3 = MagicMock()
        error_response = {
            "Error": {
                "Code": "NoSuchVersion",
                "Message": "The specified version does not exist.",
            }
        }
        mock_s3.get_object.side_effect = ClientError(error_response, "GetObject")
        with patch("common.snapshot_utils.boto3.client", return_value=mock_s3):
            result = read_snapshot(
                BUCKET,
                execution_id=EXECUTION_ID,
                control_id=CONTROL_ID,
                version_id="bogus-version-id",
            )

        assert result is None

    @mock_aws
    def test_access_denied_raises(self) -> None:
        # A non-not-found error (e.g. AccessDenied) must surface, not be reported as missing.
        from unittest.mock import MagicMock, patch

        mock_s3 = MagicMock()
        error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
        mock_s3.get_object.side_effect = ClientError(error_response, "GetObject")
        with patch("common.snapshot_utils.boto3.client", return_value=mock_s3):
            with pytest.raises(ClientError):
                read_snapshot(BUCKET, execution_id=EXECUTION_ID, control_id=CONTROL_ID)

    @mock_aws
    def test_corrupt_json_raises(self) -> None:
        # A corrupt (non-JSON) snapshot body must surface, not be reported as missing.
        _create_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        s3.put_object(
            Bucket=BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body="not-json{{{",
        )
        with pytest.raises(json.JSONDecodeError):
            read_snapshot(BUCKET, execution_id=EXECUTION_ID, control_id=CONTROL_ID)

    @mock_aws
    def test_read_with_different_control_ids(self) -> None:
        _create_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)

        data_kms = {"control": "KMS.4"}
        data_s3 = {"control": "S3.4"}
        s3.put_object(
            Bucket=BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/KMS.4.json",
            Body=json.dumps(data_kms),
        )
        s3.put_object(
            Bucket=BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/S3.4.json",
            Body=json.dumps(data_s3),
        )

        assert (
            read_snapshot(BUCKET, execution_id=EXECUTION_ID, control_id="KMS.4")
            == data_kms
        )
        assert (
            read_snapshot(BUCKET, execution_id=EXECUTION_ID, control_id="S3.4")
            == data_s3
        )


class TestValidateCommonRollbackFields:
    def test_returns_narrowed_fields_when_valid(self) -> None:
        event = {
            "AccountId": "123456789012",
            "RemediationConfigBucket": BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v-abc",
            "ExtraIgnored": "x",
        }
        fields = validate_common_rollback_fields(event)
        assert fields == {
            "AccountId": "123456789012",
            "RemediationConfigBucket": BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v-abc",
        }

    @pytest.mark.parametrize(
        "missing", ["AccountId", "RemediationConfigBucket", "ExecutionId"]
    )
    def test_missing_common_field_raises_valueerror(self, missing: str) -> None:
        event = {
            "AccountId": "123456789012",
            "RemediationConfigBucket": BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v-abc",
        }
        del event[missing]
        with pytest.raises(ValueError, match=f"Missing required parameter: {missing}"):
            validate_common_rollback_fields(event)

    def test_non_ascii_digit_account_id_raises(self) -> None:
        # str.isdigit() is True for non-ASCII digits, so a length check alone accepts strings that are not
        # AWS account ids (int() even coerces this one to 123456789012).
        event = {
            "AccountId": "１２３４５６７８９０１２",
            "RemediationConfigBucket": BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v-abc",
        }
        with pytest.raises(ValueError, match="expected 12-digit AWS account ID"):
            validate_common_rollback_fields(event)

    def test_non_12_digit_account_id_raises(self) -> None:
        event = {
            "AccountId": "123",
            "RemediationConfigBucket": BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v-abc",
        }
        with pytest.raises(ValueError, match="expected 12-digit AWS account ID"):
            validate_common_rollback_fields(event)

    def test_missing_snapshot_version_id_raises_validation_error(self) -> None:
        # Fail-closed: without the recorded version the snapshot can't be read as the exact captured object.
        event = {
            "AccountId": "123456789012",
            "RemediationConfigBucket": BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "",
        }
        with pytest.raises(
            SnapshotValidationError,
            match="Missing required parameter: SnapshotVersionId",
        ):
            validate_common_rollback_fields(event)


class TestCaptureSnapshot:
    @mock_aws
    def test_stores_and_returns_version(self) -> None:
        _create_bucket()
        is_stored, version_id = capture_snapshot(
            BUCKET,
            execution_id=EXECUTION_ID,
            account_id="123456789012",
            resource_id="arn:aws:rds:us-east-1:123456789012:cluster:c",
            control_id=CONTROL_ID,
            pre_state={"Flag": False},
            post_state={"Flag": True},
        )
        assert is_stored is True
        assert version_id != ""
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        stored = json.loads(
            s3.get_object(
                Bucket=BUCKET, Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json"
            )["Body"].read()
        )
        assert stored["preRemediationState"] == {"Flag": False}
        assert stored["postRemediationState"] == {"Flag": True}
        assert stored["resourceId"] == "arn:aws:rds:us-east-1:123456789012:cluster:c"

    @mock_aws
    def test_skips_when_bucket_or_execution_id_empty(self) -> None:
        assert capture_snapshot(
            "",
            execution_id=EXECUTION_ID,
            account_id="123456789012",
            resource_id="r",
            control_id=CONTROL_ID,
            pre_state={},
            post_state={},
        ) == (False, "")
        assert capture_snapshot(
            BUCKET,
            execution_id="",
            account_id="123456789012",
            resource_id="r",
            control_id=CONTROL_ID,
            pre_state={},
            post_state={},
        ) == (False, "")

    @mock_aws
    def test_fail_open_when_write_errors(self) -> None:
        is_stored, version_id = capture_snapshot(
            "nonexistent-bucket",
            execution_id=EXECUTION_ID,
            account_id="123456789012",
            resource_id="r",
            control_id=CONTROL_ID,
            pre_state={},
            post_state={},
        )
        assert is_stored is False
        assert version_id == ""


class TestResolveRollbackAction:
    # Bool state (RDS/DynamoDB/ElastiCache): pre=False, post=True.
    def test_bool_noop_when_current_equals_original(self) -> None:
        assert resolve_rollback_action(False, False, True) is RollbackAction.NOOP

    def test_bool_restore_when_current_equals_post(self) -> None:
        assert resolve_rollback_action(True, False, True) is RollbackAction.RESTORE

    def test_noop_takes_precedence_over_drift_on_second_rollback(self) -> None:
        # After a completed rollback current == original; must be NOOP, not DRIFT — the ordering guarantee.
        assert resolve_rollback_action(False, False, True) is RollbackAction.NOOP

    # String state (SNS): pre="" (unencrypted), post=<key>.
    def test_str_noop_when_back_to_original_unencrypted(self) -> None:
        assert resolve_rollback_action("", "", "arn:key") is RollbackAction.NOOP

    def test_str_restore_when_current_is_post_key(self) -> None:
        assert (
            resolve_rollback_action("arn:key", "", "arn:key") is RollbackAction.RESTORE
        )

    def test_drift_when_current_is_neither_original_nor_post(self) -> None:
        assert (
            resolve_rollback_action("arn:other", "", "arn:key") is RollbackAction.DRIFT
        )


class TestDispatchRollbackHandler:
    def test_routes_to_capture_when_flag_absent(self) -> None:
        def capture_fn(event: dict[str, object], context: object) -> CaptureResult:
            return {
                "snapshotStored": "true",
                "snapshotVersionId": "v1",
                "rollbackDescription": "desc",
            }

        def rollback_fn(event: dict[str, object], context: object) -> RollbackResult:
            raise AssertionError("rollback_fn must not be called on the capture path")

        result = dispatch_rollback_handler(
            {}, None, capture_fn=capture_fn, rollback_fn=rollback_fn
        )
        assert result == {
            "snapshotStored": "true",
            "snapshotVersionId": "v1",
            "rollbackDescription": "desc",
            "Message": "",
            "Status": "",
        }

    def test_routes_to_rollback_when_flag_set(self) -> None:
        def capture_fn(event: dict[str, object], context: object) -> CaptureResult:
            raise AssertionError("capture_fn must not be called on the rollback path")

        def rollback_fn(event: dict[str, object], context: object) -> RollbackResult:
            return {"Message": "restored", "Status": "SUCCESS"}

        result = dispatch_rollback_handler(
            {"Rollback": "ROLLBACK"},
            None,
            capture_fn=capture_fn,
            rollback_fn=rollback_fn,
        )
        assert result == {
            "snapshotStored": "",
            "snapshotVersionId": "",
            "rollbackDescription": "",
            "Message": "restored",
            "Status": "SUCCESS",
        }

    def test_non_string_flag_routes_to_capture(self) -> None:
        # A non-string Rollback (e.g. None from SSM) must not be coerced to "None" and mis-routed.
        def capture_fn(event: dict[str, object], context: object) -> CaptureResult:
            return {
                "snapshotStored": "true",
                "snapshotVersionId": "v1",
                "rollbackDescription": "desc",
            }

        def rollback_fn(event: dict[str, object], context: object) -> RollbackResult:
            raise AssertionError("rollback_fn must not be called")

        result = dispatch_rollback_handler(
            {"Rollback": None}, None, capture_fn=capture_fn, rollback_fn=rollback_fn
        )
        assert result["snapshotStored"] == "true"


class TestEnvelopeStateValidation:
    """Direct tests for the shared get_pre/get_post_remediation_state envelope validators."""

    _EXEC = "exec-envelope-test"

    def _snapshot(self, schema_version: int = 1, pre=None, post=None) -> dict:
        snap: dict = {
            "schemaVersion": schema_version,
            "resourceId": "res-1",
            "controlId": CONTROL_ID,
            "capturedAt": "2025-01-01T00:00:00+00:00",
        }
        if pre is not None:
            snap["preRemediationState"] = pre
        if post is not None:
            snap["postRemediationState"] = post
        return snap

    def test_get_pre_returns_state(self) -> None:
        snap = self._snapshot(pre={"Foo": False}, post={"Foo": True})
        assert get_pre_remediation_state(snap, self._EXEC) == {"Foo": False}

    def test_get_post_returns_state(self) -> None:
        snap = self._snapshot(pre={"Foo": False}, post={"Foo": True})
        assert get_post_remediation_state(snap, self._EXEC) == {"Foo": True}

    def test_get_pre_schema_mismatch_raises(self) -> None:
        snap = self._snapshot(
            schema_version=999, pre={"Foo": False}, post={"Foo": True}
        )
        with pytest.raises(SnapshotValidationError, match="schema version mismatch"):
            get_pre_remediation_state(snap, self._EXEC)

    def test_get_post_schema_mismatch_raises(self) -> None:
        snap = self._snapshot(
            schema_version=999, pre={"Foo": False}, post={"Foo": True}
        )
        with pytest.raises(SnapshotValidationError, match="schema version mismatch"):
            get_post_remediation_state(snap, self._EXEC)

    def test_get_pre_missing_state_raises(self) -> None:
        snap = self._snapshot(post={"Foo": True})  # no preRemediationState
        with pytest.raises(SnapshotValidationError, match="preRemediationState"):
            get_pre_remediation_state(snap, self._EXEC)

    def test_get_post_missing_state_raises(self) -> None:
        snap = self._snapshot(pre={"Foo": False})  # no postRemediationState
        with pytest.raises(SnapshotValidationError, match="postRemediationState"):
            get_post_remediation_state(snap, self._EXEC)
