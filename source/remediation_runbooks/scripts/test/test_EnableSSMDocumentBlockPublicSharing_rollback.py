# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for SSM.7 — EnableSSMDocumentBlockPublicSharing rollback script.

moto does not implement SSM get_service_setting/update_service_setting, so these tests inject a small
in-memory FakeSSM double for the SSM calls while using real moto-backed S3 for the snapshot bucket.
"""
from __future__ import annotations

import json
from typing import Any

import boto3
import EnableSSMDocumentBlockPublicSharing_rollback as rollback
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from moto import mock_aws
from pytest_mock import MockerFixture

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "SSM.7"
ACCOUNT_ID = "123456789012"
SETTING_ID = "/ssm/documents/console/public-sharing-permission"
ENABLE = "Enable"
DISABLE = "Disable"


class FakeSSM:
    """Minimal in-memory stand-in for the SSM service-setting API (moto does not implement it).

    Tracks the current SettingValue and records update calls. raise_on_get / raise_on_update let a
    test simulate a classified read/write failure; noop_update makes update accepted-but-ineffective.
    """

    def __init__(self, value: str = ENABLE) -> None:
        self.value = value
        self.update_calls: list[str] = []
        self.raise_on_get = False
        self.raise_on_get_first_only = False
        self._get_count = 0
        self.raise_on_update = False
        self.noop_update = False

    def get_service_setting(self, *, SettingId: str) -> dict[str, Any]:
        self._get_count += 1
        if self.raise_on_get or (self.raise_on_get_first_only and self._get_count == 1):
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException"}}, "GetServiceSetting"
            )
        return {"ServiceSetting": {"SettingId": SettingId, "SettingValue": self.value}}

    def update_service_setting(
        self, *, SettingId: str, SettingValue: str
    ) -> dict[str, Any]:
        if self.raise_on_update:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException"}}, "UpdateServiceSetting"
            )
        self.update_calls.append(SettingValue)
        if not self.noop_update:
            self.value = SettingValue
        return {}


@pytest.fixture
def fake_ssm() -> FakeSSM:
    return FakeSSM()


def _patch_ssm(mocker: MockerFixture, fake: FakeSSM) -> None:
    """Route the script's boto3.client("ssm") to the fake; other services fall through to real (moto)."""
    original_boto3_client = boto3.client
    mocker.patch(
        "EnableSSMDocumentBlockPublicSharing_rollback.boto3.client",
        side_effect=lambda service, *a, **kw: (
            fake if service == "ssm" else original_boto3_client(service, *a, **kw)
        ),
    )


def _create_snapshot_bucket() -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=SNAPSHOT_BUCKET)
    s3.put_bucket_versioning(
        Bucket=SNAPSHOT_BUCKET, VersioningConfiguration={"Status": "Enabled"}
    )


def _put_snapshot(
    execution_id: str,
    pre_value: str,
    post_value: str = DISABLE,
    schema_version: int = 1,
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = f"snapshots/{execution_id}/{CONTROL_ID}.json"
    snapshot_data = {
        "schemaVersion": schema_version,
        "resourceId": ACCOUNT_ID,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"SettingValue": pre_value},
        "postRemediationState": {"SettingValue": post_value},
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
) -> dict[str, str]:
    return {
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
    }


def _make_rollback_event(
    execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, str]:
    return {
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
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        _create_snapshot_bucket()
        fake_ssm.value = ENABLE  # originally allows public sharing (noncompliant)
        _patch_ssm(mocker, fake_ssm)

        result = rollback.capture_and_remediate(_make_capture_event(), None)

        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        assert (
            ENABLE in result["rollbackDescription"]
        )  # restore target is the original value
        assert fake_ssm.value == DISABLE  # setting now blocks public sharing

        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snapshot["preRemediationState"]["SettingValue"] == ENABLE
        assert snapshot["postRemediationState"]["SettingValue"] == DISABLE
        assert snapshot["resourceId"] == ACCOUNT_ID

    @mock_aws
    def test_no_op_when_already_disabled(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # Already blocked (pre == post) -> no-op: no snapshot written, no rollback offered, success.
        _create_snapshot_bucket()
        fake_ssm.value = DISABLE
        _patch_ssm(mocker, fake_ssm)

        result = rollback.capture_and_remediate(_make_capture_event(), None)

        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "No remediation needed" in result["rollbackDescription"]
        assert fake_ssm.value == DISABLE
        assert (
            fake_ssm.update_calls == []
        )  # already blocked -> no update issued (true no-op)
        # and no snapshot object was written
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        objects = s3.list_objects_v2(
            Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
        )
        assert objects.get("KeyCount", 0) == 0

    @mock_aws
    def test_fail_open_when_bucket_missing(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        fake_ssm.value = ENABLE
        _patch_ssm(mocker, fake_ssm)
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="nonexistent-bucket"), None
        )
        assert result["snapshotStored"] == "false"
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert fake_ssm.value == DISABLE  # remediation still applied

    @mock_aws
    def test_fail_open_when_bucket_not_provided(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        fake_ssm.value = ENABLE
        _patch_ssm(mocker, fake_ssm)
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="", execution_id=""), None
        )
        assert result["snapshotStored"] == "false"
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert fake_ssm.value == DISABLE

    @mock_aws
    def test_fail_open_when_pre_state_read_errors(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # A GetServiceSetting failure on the pre-state read must skip the snapshot but still remediate.
        _create_snapshot_bucket()
        fake_ssm.raise_on_get_first_only = True
        _patch_ssm(mocker, fake_ssm)

        result = rollback.capture_and_remediate(_make_capture_event(), None)

        assert result["snapshotStored"] == "false"
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert fake_ssm.update_calls == [DISABLE]  # remediation still applied

    @mock_aws
    def test_empty_pre_state_reports_not_rollback_able(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # A successful read can still yield "" (SettingValue absent/non-string). Capturing that would
        # advertise a rollback that execute_rollback rejects as malformed. So skip the snapshot, report
        # rollback unavailable, but still remediate.
        _create_snapshot_bucket()
        fake_ssm.value = ""  # read succeeds but value is empty
        _patch_ssm(mocker, fake_ssm)

        result = rollback.capture_and_remediate(_make_capture_event(), None)

        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert fake_ssm.value == DISABLE  # remediation still applied
        # and no snapshot object was written
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        objects = s3.list_objects_v2(
            Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
        )
        assert objects.get("KeyCount", 0) == 0

    @mock_aws
    def test_unversioned_bucket_reports_not_rollback_able(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # Versioning-disabled bucket -> no version id -> report not rollback-able (rollback would fail closed).
        boto3.client("s3", config=BOTO_CONFIG).create_bucket(
            Bucket=SNAPSHOT_BUCKET
        )  # no versioning
        fake_ssm.value = ENABLE
        _patch_ssm(mocker, fake_ssm)

        result = rollback.capture_and_remediate(_make_capture_event(), None)

        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert fake_ssm.value == DISABLE

    @mock_aws
    def test_ineffective_update_fails_remediation(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # Silently ineffective update (accepted but setting stays Enable) must fail the remediation.
        _create_snapshot_bucket()
        fake_ssm.value = ENABLE
        fake_ssm.noop_update = True
        _patch_ssm(mocker, fake_ssm)

        with pytest.raises(RuntimeError, match="expected"):
            rollback.capture_and_remediate(_make_capture_event(), None)

    def test_missing_account_id_raises(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(ValueError, match="AccountId"):
            rollback.capture_and_remediate(
                {
                    "RemediationConfigBucket": SNAPSHOT_BUCKET,
                    "AutomationExecutionId": EXECUTION_ID,
                },
                None,
            )

    def test_invalid_account_id_raises(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        _patch_ssm(mocker, fake_ssm)
        event = {
            "AccountId": "not-12-digits",
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }
        with pytest.raises(ValueError, match="12-digit"):
            rollback.capture_and_remediate(event, None)


# ═══════════════════════════════════════════════════════════════
# execute_rollback
# ═══════════════════════════════════════════════════════════════


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore(self, fake_ssm: FakeSSM, mocker: MockerFixture) -> None:
        # snapshot pre=Enable, post=Disable; setting currently Disable (post) -> restore to Enable.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_value=ENABLE)
        fake_ssm.value = DISABLE
        _patch_ssm(mocker, fake_ssm)

        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )

        assert result["Status"] == "SUCCESS"
        assert "Successfully restored" in result["Message"]
        assert fake_ssm.value == ENABLE

    @mock_aws
    def test_missing_snapshot_version_id_raises(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        _create_snapshot_bucket()
        _put_snapshot(EXECUTION_ID, pre_value=ENABLE)
        fake_ssm.value = DISABLE
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(rollback.SnapshotValidationError, match="SnapshotVersionId"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert fake_ssm.value == DISABLE  # untouched

    @mock_aws
    def test_snapshot_not_found(self, fake_ssm: FakeSSM, mocker: MockerFixture) -> None:
        _create_snapshot_bucket()
        fake_ssm.value = DISABLE
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(rollback.SnapshotNotFoundError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="missing-exec", snapshot_version_id="no-such-version"
                ),
                None,
            )
        assert fake_ssm.value == DISABLE

    @mock_aws
    def test_drift_detected_when_state_changed_after_remediation(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # Defensive test for the DRIFT gate. For a binary Enable/Disable setting, DRIFT (current != post
        # AND current != original) is only reachable when pre == post — because with pre != post, a
        # current that differs from post necessarily equals pre, which the NOOP gate catches first. A real
        # remediation never writes pre == post (the no-op path in capture_and_remediate skips the snapshot),
        # so this uses a fabricated pre=Disable/post=Disable snapshot purely to exercise the DRIFT branch:
        # the setting is now Enable, so current (Enable) != post (Disable) -> DRIFT, abort untouched.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_value=DISABLE, post_value=DISABLE)
        fake_ssm.value = ENABLE
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(rollback.SnapshotValidationError, match="modified after"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_ssm.update_calls == []  # setting untouched

    @mock_aws
    def test_idempotent_when_already_rolled_back(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # pre=Enable != post=Disable, setting currently Enable (== pre) -> idempotent no-op SUCCESS.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_value=ENABLE)
        fake_ssm.value = ENABLE
        _patch_ssm(mocker, fake_ssm)
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert fake_ssm.update_calls == []

    @mock_aws
    def test_schema_version_mismatch(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_value=ENABLE, schema_version=999)
        fake_ssm.value = DISABLE
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(
            rollback.SnapshotValidationError, match="schema version mismatch"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert fake_ssm.value == DISABLE

    @mock_aws
    def test_malformed_snapshot_missing_state(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(
                {
                    "schemaVersion": 1,
                    "resourceId": ACCOUNT_ID,
                    "preRemediationState": {},
                    "postRemediationState": {},
                }
            ),
            ContentType="application/json",
        )
        fake_ssm.value = DISABLE
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert fake_ssm.value == DISABLE

    @mock_aws
    def test_unknown_setting_value_rejected(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # SettingValue must be one of the known values (Enable/Disable). A snapshot with an unexpected
        # value fails closed rather than writing an unmodeled value back to the account setting.
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(
                {
                    "schemaVersion": 1,
                    "resourceId": ACCOUNT_ID,
                    "preRemediationState": {"SettingValue": "Sideways"},
                    "postRemediationState": {"SettingValue": DISABLE},
                }
            ),
            ContentType="application/json",
        )
        fake_ssm.value = DISABLE
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(rollback.SnapshotValidationError, match="must be one of"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert fake_ssm.value == DISABLE

    @mock_aws
    def test_corrupt_snapshot_raises_validation_error(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body="not-json{{{",
            ContentType="application/json",
        )
        fake_ssm.value = DISABLE
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )

    @mock_aws
    def test_current_state_read_error_wrapped(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # A failure on the rollback current-state (SSM) read surfaces as a classified RollbackError
        # (fail-closed) rather than a raw botocore exception.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_value=ENABLE)
        fake_ssm.raise_on_get = True
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(
            rollback.RollbackError, match="Failed to read current SSM setting"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_restore_write_error_wrapped_as_rollback_error(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # A failure on the restore update surfaces as a classified RollbackError (fail-closed).
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_value=ENABLE)
        fake_ssm.value = DISABLE
        fake_ssm.raise_on_update = True
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(rollback.RollbackError, match="Failed to restore"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_ineffective_restore_fails_rollback(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        # Silently ineffective restore (accepted but setting stays Disable) must raise RollbackError.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_value=ENABLE)
        fake_ssm.value = DISABLE
        fake_ssm.noop_update = True
        _patch_ssm(mocker, fake_ssm)
        with pytest.raises(rollback.RollbackError, match="expected"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )


# ═══════════════════════════════════════════════════════════════
# handler (single dispatch entry point)
# ═══════════════════════════════════════════════════════════════


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        _create_snapshot_bucket()
        fake_ssm.value = ENABLE
        _patch_ssm(mocker, fake_ssm)
        result = rollback.handler(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert fake_ssm.value == DISABLE

    @mock_aws
    def test_dispatches_to_execute_rollback(
        self, fake_ssm: FakeSSM, mocker: MockerFixture
    ) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_value=ENABLE)
        fake_ssm.value = DISABLE
        _patch_ssm(mocker, fake_ssm)
        event = {
            **_make_rollback_event(snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }
        result = rollback.handler(event, None)
        assert result["Status"] == "SUCCESS"
        assert result["snapshotStored"] == ""
        assert fake_ssm.value == ENABLE
