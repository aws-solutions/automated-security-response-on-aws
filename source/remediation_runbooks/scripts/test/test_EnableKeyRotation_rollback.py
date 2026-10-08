# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for KMS.4 — EnableKeyRotation rollback script.

moto implements KMS key rotation (get/enable/disable_key_rotation), so these tests use
real moto-backed clients — no fake.
"""
from __future__ import annotations

import json
from unittest import mock

import boto3
import EnableKeyRotation_rollback as rollback
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "KMS.4"
ACCOUNT_ID = "123456789012"


def _create_kms_key(rotation_enabled: bool = False) -> str:
    kms = boto3.client("kms", config=BOTO_CONFIG)
    key_id = kms.create_key(Description="Test key for KMS.4 rollback")["KeyMetadata"][
        "KeyId"
    ]
    if rotation_enabled:
        kms.enable_key_rotation(KeyId=key_id)
    return key_id


def _create_snapshot_bucket() -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=SNAPSHOT_BUCKET)
    s3.put_bucket_versioning(
        Bucket=SNAPSHOT_BUCKET, VersioningConfiguration={"Status": "Enabled"}
    )


def _put_snapshot(
    execution_id: str, rotation_enabled: bool, schema_version: int = 1
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = f"snapshots/{execution_id}/{CONTROL_ID}.json"
    snapshot_data = {
        "schemaVersion": schema_version,
        "resourceId": "test-key-id",
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"KeyRotationEnabled": rotation_enabled},
        "postRemediationState": {"KeyRotationEnabled": True},
    }
    response = s3.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=key,
        Body=json.dumps(snapshot_data),
        ContentType="application/json",
    )
    return response["VersionId"]


def _get_rotation_status(key_id: str) -> bool:
    kms = boto3.client("kms", config=BOTO_CONFIG)
    return bool(kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"])


def _make_capture_event(
    key_id: str, bucket: str = SNAPSHOT_BUCKET, execution_id: str = EXECUTION_ID
) -> dict[str, str]:
    return {
        "KeyId": key_id,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
    }


def _make_rollback_event(
    key_id: str, execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, str]:
    return {
        "KeyId": key_id,
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
        _create_snapshot_bucket()
        key_id = _create_kms_key(rotation_enabled=False)

        result = rollback.capture_and_remediate(_make_capture_event(key_id), None)

        assert result["snapshotStored"] == "true"
        assert "Disable key rotation" in result["rollbackDescription"]
        assert result["snapshotVersionId"] != ""
        assert _get_rotation_status(key_id) is True

        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snap = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snap["schemaVersion"] == 1
        assert snap["preRemediationState"]["KeyRotationEnabled"] is False
        assert snap["postRemediationState"]["KeyRotationEnabled"] is True
        assert snap["resourceId"] == key_id

    @mock_aws
    def test_fail_open_when_bucket_missing(self) -> None:
        key_id = _create_kms_key(rotation_enabled=False)
        result = rollback.capture_and_remediate(
            _make_capture_event(key_id, bucket="nonexistent-bucket"), None
        )
        assert result["snapshotStored"] == "false"
        assert _get_rotation_status(key_id) is True

    @mock_aws
    def test_fail_open_when_bucket_not_provided(self) -> None:
        key_id = _create_kms_key(rotation_enabled=False)
        result = rollback.capture_and_remediate(
            _make_capture_event(key_id, bucket="", execution_id=""), None
        )
        assert result["snapshotStored"] == "false"
        assert _get_rotation_status(key_id) is True

    @mock_aws
    def test_already_enabled_is_no_op_and_skips_snapshot(self) -> None:
        # Rotation already enabled (pre == post) -> no-op: no snapshot written, no rollback offered,
        # success. Prevents a misleading no-op rollback snapshot.
        _create_snapshot_bucket()
        key_id = _create_kms_key(rotation_enabled=True)
        result = rollback.capture_and_remediate(_make_capture_event(key_id), None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "No remediation needed" in result["rollbackDescription"]
        assert _get_rotation_status(key_id) is True
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        objs = s3.list_objects_v2(
            Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
        )
        assert objs.get("KeyCount", 0) == 0

    @mock_aws
    def test_missing_key_id_raises(self) -> None:
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }
        with pytest.raises(ValueError, match="required parameter: KeyId"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_fail_open_when_pre_state_read_errors(self) -> None:
        # GIVEN a key + bucket, but the pre-state get_key_rotation_status raises transiently.
        # The snapshot is skipped but remediation (enable) still proceeds and verifies.
        _create_snapshot_bucket()
        key_id = _create_kms_key(rotation_enabled=False)

        real_client = boto3.client
        calls = {"n": 0}

        def _client_flaky_first_read(service_name, *args, **kwargs):
            client = real_client(service_name, *args, **kwargs)
            if service_name == "kms":
                real_get = client.get_key_rotation_status

                def _get(**kw):
                    calls["n"] += 1
                    if calls["n"] == 1:  # first read = pre-state read → fail
                        raise boto3.client("kms").exceptions.KMSInternalException(
                            {
                                "Error": {
                                    "Code": "KMSInternalException",
                                    "Message": "transient",
                                }
                            },
                            "GetKeyRotationStatus",
                        )
                    return real_get(**kw)

                client.get_key_rotation_status = _get  # type: ignore[method-assign]
            return client

        with mock.patch.object(
            rollback.boto3, "client", side_effect=_client_flaky_first_read
        ):
            result = rollback.capture_and_remediate(_make_capture_event(key_id), None)

        assert result["snapshotStored"] == "false"  # snapshot skipped (fail-open)
        assert _get_rotation_status(key_id) is True  # remediation still applied

    @mock_aws
    def test_remediation_failure_propagates_after_snapshot_stored(self) -> None:
        # GIVEN a valid key + bucket, but enable_key_rotation itself fails (e.g. asymmetric key,
        # pending deletion, access denied). The snapshot is written BEFORE the enable call, so it
        # must persist, and the exception must propagate so SSM marks the step Failed.
        _create_snapshot_bucket()
        key_id = _create_kms_key(rotation_enabled=False)

        real_client = boto3.client

        def _client_enable_fails(service_name, *args, **kwargs):
            client = real_client(service_name, *args, **kwargs)
            if service_name == "kms":

                def _enable(**_kw):
                    raise boto3.client("kms").exceptions.KMSInvalidStateException(
                        {
                            "Error": {
                                "Code": "KMSInvalidStateException",
                                "Message": "pending deletion",
                            }
                        },
                        "EnableKeyRotation",
                    )

                client.enable_key_rotation = _enable  # type: ignore[method-assign]
            return client

        with mock.patch.object(
            rollback.boto3, "client", side_effect=_client_enable_fails
        ):
            with pytest.raises(ClientError, match="KMSInvalidStateException"):
                rollback.capture_and_remediate(_make_capture_event(key_id), None)

        # Snapshot was stored before the failed enable (snapshot-first): a later rollback attempt is
        # gated by the Orchestrator only marking rollbackAvailable on success, so this orphan is inert.
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snap = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snap["preRemediationState"]["KeyRotationEnabled"] is False

    @mock_aws
    def test_non_string_bucket_treated_as_absent(self) -> None:
        # A non-string RemediationConfigBucket (e.g. None from SSM) must become "" (skip snapshot),
        # NOT str(None) == "None" which would attempt an S3 write to a bucket literally named "None".
        key_id = _create_kms_key(rotation_enabled=False)
        event = {**_make_capture_event(key_id), "RemediationConfigBucket": None}
        result = rollback.capture_and_remediate(event, None)
        assert result["snapshotStored"] == "false"  # treated as absent → skipped
        assert result["snapshotVersionId"] == ""
        assert _get_rotation_status(key_id) is True  # remediation still applied


# ═══════════════════════════════════════════════════════════════
# execute_rollback
# ═══════════════════════════════════════════════════════════════


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, rotation_enabled=False)
        key_id = _create_kms_key(rotation_enabled=True)

        result = rollback.execute_rollback(
            _make_rollback_event(key_id, snapshot_version_id=version_id), None
        )

        assert result["Status"] == "SUCCESS"
        assert "Successfully restored" in result["Message"]
        assert _get_rotation_status(key_id) is False

    @mock_aws
    def test_missing_snapshot_version_id_raises(self) -> None:
        _create_snapshot_bucket()
        _put_snapshot(EXECUTION_ID, rotation_enabled=False)
        key_id = _create_kms_key(rotation_enabled=True)
        with pytest.raises(
            rollback.SnapshotValidationError, match="no snapshot version ID recorded"
        ):
            rollback.execute_rollback(
                _make_rollback_event(key_id, snapshot_version_id=""), None
            )
        assert _get_rotation_status(key_id) is True

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        _create_snapshot_bucket()
        key_id = _create_kms_key(rotation_enabled=True)
        with pytest.raises(rollback.SnapshotNotFoundError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    key_id,
                    execution_id="missing-exec",
                    snapshot_version_id="no-such-version",
                ),
                None,
            )
        assert _get_rotation_status(key_id) is True

    @mock_aws
    def test_current_equals_pre_is_idempotent_no_op(self) -> None:
        # snapshot pre=disabled/post=enabled, key currently disabled (== pre). For binary state this
        # means the key is already in its rollback-target state → idempotent no-op SUCCESS, NOT a
        # drift error. The no-op gate runs before the drift gate (idempotent second-rollback safe).
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, rotation_enabled=False
        )  # pre=disabled, post=enabled
        key_id = _create_kms_key(rotation_enabled=False)  # current == pre
        result = rollback.execute_rollback(
            _make_rollback_event(key_id, snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_rotation_status(key_id) is False

    @mock_aws
    def test_no_op_when_pre_equals_post(self) -> None:
        # pre == post == enabled, key still enabled (no drift) → no-op success.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, rotation_enabled=True)
        key_id = _create_kms_key(rotation_enabled=True)
        result = rollback.execute_rollback(
            _make_rollback_event(key_id, snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_rotation_status(key_id) is True

    @mock_aws
    def test_drift_abort_when_current_differs_from_post(self) -> None:
        # pre == post == enabled, but the key is currently disabled -> operator drift.
        # The no-op gate (current == pre) fails, so the drift gate must fire and leave the key untouched.
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, rotation_enabled=True
        )  # pre = post = enabled
        key_id = _create_kms_key(rotation_enabled=False)  # current != post
        with pytest.raises(
            rollback.SnapshotValidationError,
            match="does not match the post-remediation state",
        ):
            rollback.execute_rollback(
                _make_rollback_event(key_id, snapshot_version_id=version_id), None
            )
        assert _get_rotation_status(key_id) is False  # key left unmodified

    @mock_aws
    def test_schema_version_mismatch(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, rotation_enabled=False, schema_version=999
        )
        key_id = _create_kms_key(rotation_enabled=True)
        with pytest.raises(
            rollback.SnapshotValidationError, match="schema version mismatch"
        ):
            rollback.execute_rollback(
                _make_rollback_event(key_id, snapshot_version_id=version_id), None
            )
        assert _get_rotation_status(key_id) is True

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
        key_id = _create_kms_key(rotation_enabled=True)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(key_id, snapshot_version_id=response["VersionId"]),
                None,
            )
        assert _get_rotation_status(key_id) is True

    @mock_aws
    def test_corrupt_snapshot_raises_read_error(self) -> None:
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body="not-json{{{",
            ContentType="application/json",
        )
        key_id = _create_kms_key(rotation_enabled=True)
        with pytest.raises(rollback.SnapshotReadError, match="Failed to read snapshot"):
            rollback.execute_rollback(
                _make_rollback_event(key_id, snapshot_version_id=response["VersionId"]),
                None,
            )
        assert _get_rotation_status(key_id) is True

    @mock_aws
    def test_missing_required_param_raises(self) -> None:
        # GIVEN a rollback event missing a required param (AccountId), THEN validation raises
        # at the boundary before any AWS call.
        _create_snapshot_bucket()
        key_id = _create_kms_key(rotation_enabled=True)
        event = {
            "KeyId": key_id,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "some-version",
            # AccountId intentionally omitted
        }
        with pytest.raises(ValueError, match="Missing required parameter: AccountId"):
            rollback.execute_rollback(event, None)
        assert _get_rotation_status(key_id) is True

    @mock_aws
    def test_missing_key_id_on_rollback_raises(self) -> None:
        # GIVEN a rollback event with no KeyId, THEN validation raises at the boundary.
        _create_snapshot_bucket()
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "some-version",
        }
        with pytest.raises(ValueError, match="required parameter: KeyId"):
            rollback.execute_rollback(event, None)

    @mock_aws
    def test_restore_enables_when_original_state_was_enabled(self) -> None:
        # Guards the explicit restore branch: with a snapshot where pre=enabled/post=disabled and the
        # key currently disabled (drift gate passes, no-op gate fails), rollback must ENABLE rotation,
        # not disable it. Not reachable via today's remediation (which always sets post=True), but this
        # proves the restore branches on was_originally_enabled rather than assuming a fixed direction.
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot_data = {
            "schemaVersion": 1,
            "resourceId": "test-key-id",
            "controlId": CONTROL_ID,
            "capturedAt": "2025-01-01T00:00:00+00:00",
            "preRemediationState": {"KeyRotationEnabled": True},
            "postRemediationState": {"KeyRotationEnabled": False},
        }
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(snapshot_data),
            ContentType="application/json",
        )
        key_id = _create_kms_key(rotation_enabled=False)

        result = rollback.execute_rollback(
            _make_rollback_event(key_id, snapshot_version_id=response["VersionId"]),
            None,
        )

        assert result["Status"] == "SUCCESS"
        assert (
            _get_rotation_status(key_id) is True
        )  # restored to the original ENABLED state


# ═══════════════════════════════════════════════════════════════
# handler (single dispatch entry point)
# ═══════════════════════════════════════════════════════════════


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(self) -> None:
        _create_snapshot_bucket()
        key_id = _create_kms_key(rotation_enabled=False)
        result = rollback.handler(_make_capture_event(key_id), None)
        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert _get_rotation_status(key_id) is True

    @mock_aws
    def test_dispatches_to_execute_rollback(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, rotation_enabled=False)
        key_id = _create_kms_key(rotation_enabled=True)
        event = {
            **_make_rollback_event(key_id, snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }
        result = rollback.handler(event, None)
        assert result["Status"] == "SUCCESS"
        assert "Successfully restored" in result["Message"]
        assert result["snapshotStored"] == ""
        assert _get_rotation_status(key_id) is False


# ═══════════════════════════════════════════════════════════════
# _capture_snapshot (extracted helper)
# ═══════════════════════════════════════════════════════════════


class TestCaptureSnapshot:
    @mock_aws
    def test_stores_and_returns_version(self) -> None:
        _create_snapshot_bucket()
        stored, version_id = rollback._capture_snapshot(
            SNAPSHOT_BUCKET,
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            key_id="key-abc",
            was_rotation_enabled=False,
        )
        assert stored is True
        assert version_id != ""
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snap = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snap["preRemediationState"]["KeyRotationEnabled"] is False
        assert snap["postRemediationState"]["KeyRotationEnabled"] is True

    @mock_aws
    def test_skips_when_bucket_or_execution_id_empty(self) -> None:
        assert rollback._capture_snapshot(
            "",
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            key_id="key-abc",
            was_rotation_enabled=False,
        ) == (False, "")
        assert rollback._capture_snapshot(
            SNAPSHOT_BUCKET,
            execution_id="",
            account_id=ACCOUNT_ID,
            key_id="key-abc",
            was_rotation_enabled=False,
        ) == (False, "")

    @mock_aws
    def test_fail_open_when_write_errors(self) -> None:
        stored, version_id = rollback._capture_snapshot(
            "nonexistent-bucket",
            execution_id=EXECUTION_ID,
            account_id=ACCOUNT_ID,
            key_id="key-abc",
            was_rotation_enabled=False,
        )
        assert stored is False
        assert version_id == ""


class TestReadPreState:
    @mock_aws
    def test_returns_state_and_capable_on_success(self) -> None:
        key_id = _create_kms_key(rotation_enabled=True)
        kms = boto3.client("kms", config=BOTO_CONFIG)
        assert rollback._read_pre_state(kms, key_id) == (True, True)

    @mock_aws
    def test_fail_open_returns_false_false_on_error(self) -> None:
        # A read error must return (False, False): snapshot skipped, remediation still proceeds.
        from botocore.exceptions import BotoCoreError

        class _RaisingKms:
            def get_key_rotation_status(self, **_kw):
                raise BotoCoreError()

        assert rollback._read_pre_state(_RaisingKms(), "key-abc") == (False, False)
