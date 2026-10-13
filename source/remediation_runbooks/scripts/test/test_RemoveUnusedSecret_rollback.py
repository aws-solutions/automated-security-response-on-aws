# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for SecretsManager.3 — RemoveUnusedSecret rollback script.

moto implements Secrets Manager describe_secret/delete_secret/restore_secret, including setting and
clearing DeletedDate, so the capture and rollback paths run against real moto-backed clients.

One gap matters: moto NEVER populates LastAccessedDate — not even after get_secret_value — so a
moto-backed secret can never satisfy the "unused beyond threshold" check. The threshold logic is
therefore covered directly by unit tests against _is_unused_beyond_threshold, and the integration tests
patch that helper so they can exercise the real describe/delete/restore and S3 snapshot paths. The
refusal path is tested WITHOUT the patch, so it exercises the genuine moto response.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
import pytest
import RemoveUnusedSecret_rollback as rollback
from botocore.config import Config
from botocore.exceptions import ClientError
from common.snapshot_utils import (  # noqa: E402
    ResourceNotFoundError,
    SnapshotNotFoundError,
    SnapshotReadError,
    SnapshotValidationError,
)
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "SecretsManager.3"
ACCOUNT_ID = "123456789012"
SECRET_NAME = "asr-test-secret"
UNUSED_FOR_DAYS = 90


def _create_secret() -> str:
    secretsmanager = boto3.client("secretsmanager", config=BOTO_CONFIG)
    return str(
        secretsmanager.create_secret(Name=SECRET_NAME, SecretString="test-value")[
            "ARN"
        ]  # NOSONAR test-only fixture value
    )


def _create_snapshot_bucket() -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=SNAPSHOT_BUCKET)
    s3.put_bucket_versioning(
        Bucket=SNAPSHOT_BUCKET, VersioningConfiguration={"Status": "Enabled"}
    )


def _describe(secret_arn: str) -> dict[str, Any]:
    secretsmanager = boto3.client("secretsmanager", config=BOTO_CONFIG)
    return dict(secretsmanager.describe_secret(SecretId=secret_arn))


def _is_scheduled(secret_arn: str) -> bool:
    return _describe(secret_arn).get("DeletedDate") is not None


def _put_snapshot(
    secret_arn: str,
    execution_id: str = EXECUTION_ID,
    *,
    pre_scheduled: bool = False,
    post_scheduled: bool = True,
    schema_version: int = 1,
    resource_id: str | None = None,
    omit_pre_state_flag: bool = False,
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = f"snapshots/{execution_id}/{CONTROL_ID}.json"
    pre_state: dict[str, Any] = (
        {} if omit_pre_state_flag else {"IsScheduledForDeletion": pre_scheduled}
    )
    data = {
        "schemaVersion": schema_version,
        "resourceId": resource_id if resource_id is not None else secret_arn,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": pre_state,
        "postRemediationState": {"IsScheduledForDeletion": post_scheduled},
    }
    return str(
        s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=key,
            Body=json.dumps(data),
            ContentType="application/json",
        )["VersionId"]
    )


def _make_capture_event(
    secret_arn: str,
    *,
    config_bucket: str = SNAPSHOT_BUCKET,
    execution_id: str = EXECUTION_ID,
) -> dict[str, object]:
    return {
        "SecretARN": secret_arn,
        "AccountId": ACCOUNT_ID,
        "UnusedForDays": UNUSED_FOR_DAYS,
        "RemediationConfigBucket": config_bucket,
        "AutomationExecutionId": execution_id,
    }


def _make_rollback_event(
    secret_arn: str, *, execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, object]:
    return {
        "SecretARN": secret_arn,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": execution_id,
        "SnapshotVersionId": snapshot_version_id,
    }


@pytest.fixture
def force_unused(monkeypatch: pytest.MonkeyPatch) -> None:
    """moto never sets LastAccessedDate, so the threshold check can only be satisfied by patching it.
    The threshold logic itself is covered by the unit tests below."""
    monkeypatch.setattr(
        rollback, "_is_unused_beyond_threshold", lambda secret, days: True
    )


# ── unit: validation / helpers ───────────────────────────────────────────────


def test_validate_secret_arn_rejects_non_secret_arn() -> None:
    with pytest.raises(ValueError, match="SecretARN"):
        rollback._validate_secret_arn({"SecretARN": "arn:aws:s3:::not-a-secret"})


def test_validate_unused_for_days_accepts_int_and_digit_string() -> None:
    assert rollback._validate_unused_for_days({"UnusedForDays": 90}) == 90
    assert rollback._validate_unused_for_days({"UnusedForDays": "0"}) == 0


def test_validate_unused_for_days_rejects_bool_and_out_of_range() -> None:
    # bool is an int subclass, so it must be rejected explicitly.
    with pytest.raises(ValueError, match="UnusedForDays"):
        rollback._validate_unused_for_days({"UnusedForDays": True})
    with pytest.raises(ValueError, match="UnusedForDays"):
        rollback._validate_unused_for_days({"UnusedForDays": 1000})
    # A negative retention threshold is nonsensical; only an int can carry one ("-1".isdigit() is False).
    with pytest.raises(ValueError, match="UnusedForDays"):
        rollback._validate_unused_for_days({"UnusedForDays": -1})
    with pytest.raises(ValueError, match="UnusedForDays"):
        rollback._validate_unused_for_days({"UnusedForDays": "ninety"})
    with pytest.raises(ValueError, match="UnusedForDays"):
        rollback._validate_unused_for_days({})


def test_validate_account_id_rejects_unicode_digits() -> None:
    # str.isdigit() accepts full-width digits, which are not valid AWS account IDs.
    with pytest.raises(ValueError, match="12-digit"):
        rollback._validate_account_id(
            {
                "AccountId": "\uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff18\uff19\uff10\uff11\uff12"
            }
        )


def test_is_unused_beyond_threshold_requires_last_accessed_date() -> None:
    # A secret with no LastAccessedDate is NOT deleted (preserves the pre-rollback behaviour).
    assert rollback._is_unused_beyond_threshold({}, 90) is False


def test_is_unused_beyond_threshold_compares_against_threshold() -> None:
    now = datetime.now(timezone.utc)
    assert (
        rollback._is_unused_beyond_threshold(
            {"LastAccessedDate": now - timedelta(days=100)}, 90
        )
        is True
    )
    assert (
        rollback._is_unused_beyond_threshold(
            {"LastAccessedDate": now - timedelta(days=10)}, 90
        )
        is False
    )
    # Exactly at the threshold is not "beyond" it.
    assert (
        rollback._is_unused_beyond_threshold(
            {"LastAccessedDate": now - timedelta(days=90)}, 90
        )
        is False
    )


def test_is_scheduled_for_deletion_reads_deleted_date() -> None:
    assert rollback._is_scheduled_for_deletion({}) is False
    assert (
        rollback._is_scheduled_for_deletion({"DeletedDate": datetime.now(timezone.utc)})
        is True
    )


# ── capture_and_remediate ────────────────────────────────────────────────────


class TestCaptureAndRemediate:
    @mock_aws
    def test_successful_snapshot_and_remediation(self, force_unused: None) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()

        result = rollback.capture_and_remediate(_make_capture_event(secret_arn), None)

        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        assert "Cancel the scheduled deletion" in result["rollbackDescription"]
        assert _is_scheduled(secret_arn) is True
        snap = json.loads(
            boto3.client("s3", config=BOTO_CONFIG)
            .get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"]
            .read()
        )
        assert snap["resourceId"] == secret_arn
        assert snap["preRemediationState"] == {"IsScheduledForDeletion": False}
        assert snap["postRemediationState"] == {"IsScheduledForDeletion": True}

    @mock_aws
    def test_refuses_when_secret_recently_accessed(self) -> None:
        # No force_unused patch: moto returns no LastAccessedDate, so the real check refuses.
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        with pytest.raises(rollback.RemediationError, match="accessed within the past"):
            rollback.capture_and_remediate(_make_capture_event(secret_arn), None)
        assert _is_scheduled(secret_arn) is False

    @mock_aws
    def test_no_op_when_already_scheduled_for_deletion(
        self, force_unused: None
    ) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        boto3.client("secretsmanager", config=BOTO_CONFIG).delete_secret(
            SecretId=secret_arn, RecoveryWindowInDays=30
        )

        result = rollback.capture_and_remediate(_make_capture_event(secret_arn), None)

        assert result["snapshotStored"] == "false"
        assert "already scheduled for deletion" in result["rollbackDescription"]
        objs = boto3.client("s3", config=BOTO_CONFIG).list_objects_v2(
            Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
        )
        assert objs.get("KeyCount", 0) == 0

    @mock_aws
    def test_fail_open_when_config_bucket_missing(self, force_unused: None) -> None:
        secret_arn = _create_secret()
        result = rollback.capture_and_remediate(
            _make_capture_event(secret_arn, config_bucket="nonexistent-bucket"), None
        )
        assert result["snapshotStored"] == "false"
        assert "Rollback unavailable" in result["rollbackDescription"]
        # Fail-open: the security remediation still happened.
        assert _is_scheduled(secret_arn) is True

    @mock_aws
    def test_secret_not_found_raises(self, force_unused: None) -> None:
        _create_snapshot_bucket()
        with pytest.raises(ResourceNotFoundError, match="not found"):
            rollback.capture_and_remediate(
                _make_capture_event(
                    f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:missing-AbCdEf"
                ),
                None,
            )

    @mock_aws
    def test_invalid_account_id_raises(self, force_unused: None) -> None:
        secret_arn = _create_secret()
        with pytest.raises(ValueError, match="12-digit"):
            rollback.capture_and_remediate(
                {**_make_capture_event(secret_arn), "AccountId": "123"}, None
            )

    @mock_aws
    def test_verification_failure_after_delete_raises(
        self, force_unused: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Fail-closed guarantee: if the secret is not scheduled for deletion after DeleteSecret, the
        # remediation must not report success. Forcing the flag False makes the no-op guard pass and the
        # post-delete read-back fail, which is the branch under test.
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        monkeypatch.setattr(
            rollback, "_is_scheduled_for_deletion", lambda secret: False
        )
        with pytest.raises(rollback.RemediationError, match="Verification failed"):
            rollback.capture_and_remediate(_make_capture_event(secret_arn), None)


# ── execute_rollback ─────────────────────────────────────────────────────────


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        version_id = _put_snapshot(secret_arn)
        boto3.client("secretsmanager", config=BOTO_CONFIG).delete_secret(
            SecretId=secret_arn, RecoveryWindowInDays=30
        )
        assert _is_scheduled(secret_arn) is True

        result = rollback.execute_rollback(
            _make_rollback_event(secret_arn, snapshot_version_id=version_id), None
        )

        assert result["Status"] == "SUCCESS"
        assert "Successfully cancelled the scheduled deletion" in result["Message"]
        assert _is_scheduled(secret_arn) is False

    @mock_aws
    def test_noop_when_not_scheduled_for_deletion(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        version_id = _put_snapshot(secret_arn)

        result = rollback.execute_rollback(
            _make_rollback_event(secret_arn, snapshot_version_id=version_id), None
        )

        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]

    @mock_aws
    def test_idempotent_second_rollback(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        version_id = _put_snapshot(secret_arn)
        boto3.client("secretsmanager", config=BOTO_CONFIG).delete_secret(
            SecretId=secret_arn, RecoveryWindowInDays=30
        )
        rollback.execute_rollback(
            _make_rollback_event(secret_arn, snapshot_version_id=version_id), None
        )
        result = rollback.execute_rollback(
            _make_rollback_event(secret_arn, snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]

    @mock_aws
    def test_secret_permanently_deleted_fails_closed(self) -> None:
        # The recovery window elapsed and the secret is gone: rollback must fail, not report success.
        _create_snapshot_bucket()
        missing_arn = (
            f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:secret:gone-AbCdEf"
        )
        version_id = _put_snapshot(missing_arn)
        with pytest.raises(ResourceNotFoundError, match="recovery window has elapsed"):
            rollback.execute_rollback(
                _make_rollback_event(missing_arn, snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_restore_on_a_destroyed_secret_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        version_id = _put_snapshot(secret_arn)
        boto3.client("secretsmanager", config=BOTO_CONFIG).delete_secret(
            SecretId=secret_arn, RecoveryWindowInDays=30
        )

        real_client = rollback.boto3.client

        def _client_with_failing_restore(
            service_name: str, *args: object, **kwargs: object
        ) -> Any:
            client = real_client(service_name, *args, **kwargs)
            if service_name == "secretsmanager":

                def _restore(**_kwargs: object) -> None:
                    raise ClientError(
                        {
                            "Error": {
                                "Code": "ResourceNotFoundException",
                                "Message": "can't find the specified secret",
                            }
                        },
                        "RestoreSecret",
                    )

                monkeypatch.setattr(client, "restore_secret", _restore, raising=False)
            return client

        monkeypatch.setattr(rollback.boto3, "client", _client_with_failing_restore)
        with pytest.raises(ResourceNotFoundError, match="recovery window has elapsed"):
            rollback.execute_rollback(
                _make_rollback_event(secret_arn, snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_missing_snapshot_version_id_raises(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        _put_snapshot(secret_arn)
        boto3.client("secretsmanager", config=BOTO_CONFIG).delete_secret(
            SecretId=secret_arn, RecoveryWindowInDays=30
        )
        with pytest.raises(SnapshotValidationError, match="SnapshotVersionId"):
            rollback.execute_rollback(
                _make_rollback_event(secret_arn, snapshot_version_id=""), None
            )
        # Fail-closed: the secret is left scheduled for deletion.
        assert _is_scheduled(secret_arn) is True

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        with pytest.raises(SnapshotNotFoundError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    secret_arn,
                    execution_id="missing",
                    snapshot_version_id="no-such-version",
                ),
                None,
            )

    @mock_aws
    def test_resource_id_mismatch_raises(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        version_id = _put_snapshot(
            secret_arn,
            resource_id="arn:aws:secretsmanager:us-east-1:123456789012:secret:other-AbCdEf",
        )
        with pytest.raises(
            SnapshotValidationError, match="does not match the target secret"
        ):
            rollback.execute_rollback(
                _make_rollback_event(secret_arn, snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_schema_version_mismatch(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        version_id = _put_snapshot(secret_arn, schema_version=999)
        with pytest.raises(SnapshotValidationError, match="schema version mismatch"):
            rollback.execute_rollback(
                _make_rollback_event(secret_arn, snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_malformed_snapshot_missing_flag(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        version_id = _put_snapshot(secret_arn, omit_pre_state_flag=True)
        with pytest.raises(SnapshotValidationError, match="IsScheduledForDeletion"):
            rollback.execute_rollback(
                _make_rollback_event(secret_arn, snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_verification_failure_after_restore_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Fail-closed guarantee: if the secret is still scheduled for deletion after RestoreSecret, the
        # rollback must report failure (SSM then surfaces ROLLBACK_FAILED) rather than a false success.
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        version_id = _put_snapshot(secret_arn)
        boto3.client("secretsmanager", config=BOTO_CONFIG).delete_secret(
            SecretId=secret_arn, RecoveryWindowInDays=30
        )
        monkeypatch.setattr(rollback, "_is_scheduled_for_deletion", lambda secret: True)
        with pytest.raises(
            rollback.RollbackError, match="Rollback verification failed"
        ):
            rollback.execute_rollback(
                _make_rollback_event(secret_arn, snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_snapshot_read_failure_raises_snapshot_read_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A snapshot read that fails for a reason other than absence (e.g. AccessDenied) must fail closed as
        # SnapshotReadError, not be mistaken for "no snapshot".
        _create_snapshot_bucket()
        secret_arn = _create_secret()

        def _raise(*_args: object, **_kwargs: object) -> None:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetObject"
            )

        monkeypatch.setattr(rollback, "read_snapshot", _raise)
        with pytest.raises(SnapshotReadError, match="Failed to read snapshot"):
            rollback.execute_rollback(
                _make_rollback_event(secret_arn, snapshot_version_id="v"), None
            )

    @mock_aws
    def test_rollback_path_rejects_unicode_digit_account_id(self) -> None:
        # Regression: the shared validate_common_rollback_fields checks only isdigit()+length, which accepts
        # full-width digits. The rollback path must be as strict as the capture path, not weaker.
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        full_width_account = "\uff11" * 12
        event = {
            **_make_rollback_event(secret_arn, snapshot_version_id="v"),
            "AccountId": full_width_account,
        }
        with pytest.raises(ValueError, match="12-digit"):
            rollback.execute_rollback(event, None)

    @mock_aws
    def test_missing_account_id_raises(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        event = {
            "SecretARN": secret_arn,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v",
        }
        with pytest.raises(ValueError, match="Missing required parameter: AccountId"):
            rollback.execute_rollback(event, None)


# ── handler dispatch ─────────────────────────────────────────────────────────


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(self, force_unused: None) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        result = rollback.handler(_make_capture_event(secret_arn), None)
        assert result["snapshotStored"] == "true"
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert _is_scheduled(secret_arn) is True

    @mock_aws
    def test_dispatches_to_execute_rollback(self) -> None:
        _create_snapshot_bucket()
        secret_arn = _create_secret()
        version_id = _put_snapshot(secret_arn)
        boto3.client("secretsmanager", config=BOTO_CONFIG).delete_secret(
            SecretId=secret_arn, RecoveryWindowInDays=30
        )
        event = {
            **_make_rollback_event(secret_arn, snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }
        result = rollback.handler(event, None)
        assert result["Status"] == "SUCCESS"
        assert result["snapshotStored"] == ""
        assert _is_scheduled(secret_arn) is False
