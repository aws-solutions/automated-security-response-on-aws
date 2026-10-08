# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for RDS.6 — EnableEnhancedMonitoringOnRDSInstance rollback script.

moto implements RDS describe_db_instances/modify_db_instance (including
MonitoringInterval/MonitoringRoleArn), so these tests use real moto-backed
clients — no fake.
"""
from __future__ import annotations

import json

import boto3
import EnableEnhancedMonitoringOnRDSInstance_rollback as rollback
import pytest
from botocore.config import Config
from botocore.exceptions import BotoCoreError
from botocore.stub import Stubber
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "RDS.6"
DB_INSTANCE_ID = "test-instance"
RDS_INSTANCE_ARN = "arn:aws:rds:us-east-1:123456789012:db:test-instance"
ACCOUNT_ID = "123456789012"
MONITORING_ROLE_ARN = "arn:aws:iam::123456789012:role/rds-monitoring"


def _create_instance(monitoring_interval: int = 0) -> None:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    rds.create_db_instance(
        DBInstanceIdentifier=DB_INSTANCE_ID,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        AllocatedStorage=20,
        MasterUsername="admin",
        MasterUserPassword="Password123!",  # NOSONAR test-only fixture credential
    )
    if monitoring_interval != 0:
        rds.modify_db_instance(
            DBInstanceIdentifier=DB_INSTANCE_ID,
            MonitoringInterval=monitoring_interval,
            MonitoringRoleArn=MONITORING_ROLE_ARN,
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
    pre_interval: int,
    pre_role: str = "",
    post_interval: int = 60,
    post_role: str = MONITORING_ROLE_ARN,
    schema_version: int = 1,
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = f"snapshots/{execution_id}/{CONTROL_ID}.json"
    snapshot_data = {
        "schemaVersion": schema_version,
        "resourceId": RDS_INSTANCE_ARN,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {
            "MonitoringInterval": pre_interval,
            "MonitoringRoleArn": pre_role,
        },
        "postRemediationState": {
            "MonitoringInterval": post_interval,
            "MonitoringRoleArn": post_role,
        },
    }
    response = s3.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=key,
        Body=json.dumps(snapshot_data),
        ContentType="application/json",
    )
    return response["VersionId"]


def _get_monitoring_interval() -> int:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    return (
        rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)["DBInstances"][
            0
        ].get("MonitoringInterval", 0)
        or 0
    )


def _get_monitoring_role() -> str:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    return rds.describe_db_instances(DBInstanceIdentifier=DB_INSTANCE_ID)[
        "DBInstances"
    ][0].get("MonitoringRoleArn", "")


def _make_capture_event(
    *,
    bucket: str = SNAPSHOT_BUCKET,
    execution_id: str = EXECUTION_ID,
    monitoring_interval: int = 60,
) -> dict[str, object]:
    return {
        "RDSInstanceARN": RDS_INSTANCE_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
        "MonitoringInterval": monitoring_interval,
        "MonitoringRoleArn": MONITORING_ROLE_ARN,
    }


def _make_rollback_event(
    *, execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, object]:
    return {
        "RDSInstanceARN": RDS_INSTANCE_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": execution_id,
        "SnapshotVersionId": snapshot_version_id,
    }


def test_validate_monitoring_interval_accepts_int_and_string() -> None:
    # SSM may serialize the Integer parameter as an int or a string; both must parse.
    assert rollback._validate_monitoring_interval(60) == 60
    assert rollback._validate_monitoring_interval("15") == 15


def test_validate_monitoring_interval_rejects_zero() -> None:
    # 0 (disabled) is valid only as a captured pre-remediation state, never as a remediation target:
    # RDS.6 enables enhanced monitoring, so a target of 0 (which would disable it) must be rejected.
    with pytest.raises(ValueError, match="expected one of"):
        rollback._validate_monitoring_interval(0)


def test_validate_monitoring_interval_invalid_raises() -> None:
    with pytest.raises(ValueError, match="Invalid MonitoringInterval"):
        rollback._validate_monitoring_interval("sometimes")


def test_validate_monitoring_interval_out_of_range_raises() -> None:
    with pytest.raises(ValueError, match="expected one of"):
        rollback._validate_monitoring_interval(7)


def test_validate_apply_immediately_valid() -> None:
    assert rollback._validate_apply_immediately("true") is True
    assert rollback._validate_apply_immediately("false") is False
    assert rollback._validate_apply_immediately(True) is True


def test_validate_apply_immediately_invalid_raises() -> None:
    with pytest.raises(ValueError, match="Invalid ApplyImmediately"):
        rollback._validate_apply_immediately("yes")


def test_optional_str_narrows_non_strings() -> None:
    # Non-string values narrow to "" (fail-open) rather than coercing to bogus strings like "None".
    assert rollback._optional_str("bucket") == "bucket"
    assert rollback._optional_str(None) == ""
    assert rollback._optional_str(123) == ""


def test_monitoring_state_key_drops_role_when_disabled() -> None:
    # Role is kept when monitoring is enabled, normalized to "" when disabled (interval 0) — so a completed
    # rollback to a disabled state compares equal to the pre-state despite RDS retaining a stale role ARN.
    assert rollback._monitoring_state_key(60, "roleA") == (60, "roleA")
    assert rollback._monitoring_state_key(0, "stale-role") == (0, "")


def test_validate_monitoring_interval_non_int_type_raises() -> None:
    # A value that is neither int nor str hits the final else branch.
    with pytest.raises(ValueError, match="expected an integer"):
        rollback._validate_monitoring_interval(None)


def test_validate_rollback_event_missing_field_raises() -> None:
    # A rollback event missing a required string field (AccountId) fails at the boundary.
    event = {
        "RDSInstanceARN": RDS_INSTANCE_ARN,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": EXECUTION_ID,
        "SnapshotVersionId": "v1",
    }
    with pytest.raises(ValueError, match="Missing required parameter: AccountId"):
        rollback._validate_rollback_event(event)


def test_get_monitoring_state_unexpected_interval_raises(mocker) -> None:
    fake_rds = mocker.Mock()
    fake_rds.describe_db_instances.return_value = {
        "DBInstances": [{"MonitoringInterval": 7, "MonitoringRoleArn": ""}]
    }
    with pytest.raises(RuntimeError, match="unexpected MonitoringInterval"):
        rollback._get_monitoring_state(fake_rds, DB_INSTANCE_ID)


# ═══════════════════════════════════════════════════════════════
# capture_and_remediate
# ═══════════════════════════════════════════════════════════════


class TestCaptureAndRemediate:
    @mock_aws
    def test_successful_snapshot_and_remediation(self) -> None:
        # GIVEN an instance with monitoring disabled (interval 0) and a snapshot bucket
        _create_snapshot_bucket()
        _create_instance(monitoring_interval=0)

        # WHEN capture_and_remediate is called
        result = rollback.capture_and_remediate(_make_capture_event(), None)

        # THEN the snapshot is stored and monitoring is enabled at the target interval
        assert result["snapshotStored"] == "true"
        assert (
            "Restore enhanced monitoring interval to 0" in result["rollbackDescription"]
        )
        assert _get_monitoring_interval() == 60
        assert result["snapshotVersionId"] != ""

        # AND the snapshot in S3 reflects the original disabled state and the applied target
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snapshot["schemaVersion"] == 1
        assert snapshot["preRemediationState"]["MonitoringInterval"] == 0
        assert snapshot["postRemediationState"]["MonitoringInterval"] == 60
        assert snapshot["resourceId"] == RDS_INSTANCE_ARN

    @mock_aws
    def test_fail_open_when_bucket_missing(self) -> None:
        # GIVEN no snapshot bucket exists
        _create_instance(monitoring_interval=0)

        # WHEN capture_and_remediate is called THEN snapshot write fails but remediation still proceeds
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="nonexistent-bucket"), None
        )
        assert result["snapshotStored"] == "false"
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_fail_open_when_bucket_not_provided(self) -> None:
        # GIVEN empty bucket/execution config
        _create_instance(monitoring_interval=0)

        # WHEN capture_and_remediate is called THEN snapshot is skipped but remediation still proceeds
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="", execution_id=""), None
        )
        assert result["snapshotStored"] == "false"
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_unversioned_bucket_reports_not_stored(self) -> None:
        # A stored-but-unversioned snapshot has no version id; rollback reads by version id, so report
        # snapshotStored="false" (rollback would be impossible) while remediation still proceeds.
        boto3.client("s3", config=BOTO_CONFIG).create_bucket(Bucket=SNAPSHOT_BUCKET)
        _create_instance(monitoring_interval=0)
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_already_at_target_skips_snapshot_and_remediation(self) -> None:
        # GIVEN an instance already at the exact target (interval 60 + the target role)
        _create_snapshot_bucket()
        _create_instance(monitoring_interval=60)

        # WHEN capture_and_remediate is called THEN it is a no-op: no snapshot written, no change
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "No remediation needed" in result["rollbackDescription"]
        assert _get_monitoring_interval() == 60
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        assert (
            s3.list_objects_v2(
                Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
            ).get("KeyCount", 0)
            == 0
        )

    @mock_aws
    def test_role_differs_at_same_interval_remediates(self) -> None:
        # GIVEN interval already 60 but a different target role — not a no-op; must remediate to set the role.
        _create_snapshot_bucket()
        _create_instance(monitoring_interval=60)  # current role = MONITORING_ROLE_ARN
        other_role = "arn:aws:iam::123456789012:role/other-monitoring"
        result = rollback.capture_and_remediate(
            {**_make_capture_event(), "MonitoringRoleArn": other_role}, None
        )
        assert result["snapshotStored"] == "true"
        assert _get_monitoring_interval() == 60
        assert _get_monitoring_role() == other_role

    @mock_aws
    def test_cross_account_arn_rejected(self) -> None:
        # GIVEN an ARN whose embedded account differs from AccountId (cross-account defense-in-depth)
        _create_instance(monitoring_interval=0)
        event = {
            **_make_capture_event(),
            "RDSInstanceARN": "arn:aws:rds:us-east-1:999999999999:db:test-instance",
        }
        with pytest.raises(ValueError, match="does not match the executing account"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_fail_open_when_prestate_read_errors(self, mocker) -> None:
        # GIVEN the pre-state read hits a transient error THEN the snapshot is skipped but remediation proceeds.
        # _get_monitoring_state is stubbed (not moto) on purpose: the fail-open path handles a *transient*
        # ClientError/BotoCoreError on the first read that then clears on retry — moto can't produce an error
        # that fails once and then succeeds. A missing instance would instead raise ResourceNotFoundError,
        # which is deliberately NOT fail-open, so it can't drive this path either.
        _create_snapshot_bucket()
        _create_instance(monitoring_interval=0)
        original = rollback._get_monitoring_state
        calls = {"n": 0}

        def flaky(
            rds, db_instance_id
        ):  # first call = pre-state read (fails); later = verify (real)
            calls["n"] += 1
            if calls["n"] == 1:
                raise BotoCoreError()
            return original(rds, db_instance_id)

        mocker.patch.object(rollback, "_get_monitoring_state", side_effect=flaky)
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "false"
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_missing_required_parameter_raises(self) -> None:
        # GIVEN an event missing the required RDSInstanceARN
        _create_instance(monitoring_interval=0)
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }
        with pytest.raises(ValueError, match="RDSInstanceARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_invalid_resource_arn_raises(self) -> None:
        # GIVEN an ARN that is not an RDS DB instance ARN
        _create_instance(monitoring_interval=0)
        event = {
            "RDSInstanceARN": "not-an-arn",
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
            "MonitoringRoleArn": MONITORING_ROLE_ARN,
        }
        with pytest.raises(ValueError, match="expected an RDS DB instance ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_missing_account_id_raises(self) -> None:
        # GIVEN an event missing AccountId (drops the S3 ExpectedBucketOwner assertion, CWE-283)
        _create_instance(monitoring_interval=0)
        event = {
            "RDSInstanceARN": RDS_INSTANCE_ARN,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
            "MonitoringRoleArn": MONITORING_ROLE_ARN,
        }
        with pytest.raises(ValueError, match="AccountId"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_non_arn_with_db_marker_raises(self) -> None:
        # GIVEN a string that contains ":db:" but is not an arn: (must not slip past the boundary)
        _create_instance(monitoring_interval=0)
        event = {
            "RDSInstanceARN": "foo:db:test-instance",
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
            "MonitoringRoleArn": MONITORING_ROLE_ARN,
        }
        with pytest.raises(ValueError, match="expected an RDS DB instance ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_enabling_without_role_raises(self) -> None:
        # GIVEN enabling monitoring (interval 60) but no MonitoringRoleArn — the RDS API requires one
        _create_snapshot_bucket()
        _create_instance(monitoring_interval=0)
        event = {**_make_capture_event(), "MonitoringRoleArn": ""}
        # WHEN capture_and_remediate is called THEN it fails early with a clear error (not a confusing RDS error)
        with pytest.raises(ValueError, match="MonitoringRoleArn is required"):
            rollback.capture_and_remediate(event, None)

    def test_modify_monitoring_forwards_apply_immediately_false(self, mocker) -> None:
        # Exercise the non-default ApplyImmediately=false path: it must be forwarded to ModifyDBInstance.
        # Mock is at the boto3 boundary (the RDS client), not on our own code. moto doesn't surface
        # ApplyImmediately back via describe, so asserting the forwarded call arg is the way to cover it.
        fake_rds = mocker.Mock()
        rollback._modify_monitoring(
            fake_rds,
            DB_INSTANCE_ID,
            interval=60,
            role=MONITORING_ROLE_ARN,
            apply_immediately=False,
        )
        _, kwargs = fake_rds.modify_db_instance.call_args
        assert kwargs["ApplyImmediately"] is False
        assert kwargs["MonitoringInterval"] == 60
        assert kwargs["MonitoringRoleArn"] == MONITORING_ROLE_ARN

    def test_modify_monitoring_omits_role_at_zero(self, mocker) -> None:
        # interval 0 disables enhanced monitoring; the RDS API requires MonitoringRoleArn to be omitted then.
        # Mock is at the boto3 boundary (the RDS client), not our own code.
        fake_rds = mocker.Mock()
        rollback._modify_monitoring(
            fake_rds, DB_INSTANCE_ID, interval=0, role="", apply_immediately=True
        )
        _, kwargs = fake_rds.modify_db_instance.call_args
        assert "MonitoringRoleArn" not in kwargs
        assert kwargs["MonitoringInterval"] == 0
        assert kwargs["ApplyImmediately"] is True


# ═══════════════════════════════════════════════════════════════
# execute_rollback
# ═══════════════════════════════════════════════════════════════


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore_to_disabled(self) -> None:
        # GIVEN a snapshot (pre=0, post=60) and the instance in the post-remediation state (60)
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_interval=0)
        _create_instance(monitoring_interval=60)

        # WHEN execute_rollback is called THEN monitoring is disabled (interval 0)
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "Successfully restored monitoring interval to 0" in result["Message"]
        assert _get_monitoring_interval() == 0

    @mock_aws
    def test_restore_to_nonzero_interval_includes_role(self) -> None:
        # GIVEN a snapshot with a non-zero pre interval (15) and post 60, instance at 60
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, pre_interval=15, pre_role=MONITORING_ROLE_ARN
        )
        _create_instance(monitoring_interval=60)

        # WHEN execute_rollback is called THEN it restores interval 15 and re-passes the role
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert _get_monitoring_interval() == 15
        assert _get_monitoring_role() == MONITORING_ROLE_ARN

    @mock_aws
    def test_missing_snapshot_version_id_raises(self) -> None:
        # GIVEN a valid snapshot but no version id supplied (tamper-proof read impossible)
        _create_snapshot_bucket()
        _put_snapshot(EXECUTION_ID, pre_interval=0)
        _create_instance(monitoring_interval=60)
        with pytest.raises(RuntimeError, match="SnapshotVersionId"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        # GIVEN a snapshot bucket exists but has no snapshot for this execution
        _create_snapshot_bucket()
        _create_instance(monitoring_interval=60)
        with pytest.raises(RuntimeError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="missing-exec", snapshot_version_id="no-such-version"
                ),
                None,
            )
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_snapshot_resource_id_mismatch_raises(self) -> None:
        # GIVEN a snapshot whose resourceId is a different instance
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot_data = {
            "schemaVersion": 1,
            "resourceId": "arn:aws:rds:us-east-1:123456789012:db:other-instance",
            "controlId": CONTROL_ID,
            "capturedAt": "2025-01-01T00:00:00+00:00",
            "preRemediationState": {"MonitoringInterval": 0, "MonitoringRoleArn": ""},
            "postRemediationState": {
                "MonitoringInterval": 60,
                "MonitoringRoleArn": MONITORING_ROLE_ARN,
            },
        }
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(snapshot_data),
            ContentType="application/json",
        )
        _create_instance(monitoring_interval=60)
        with pytest.raises(
            RuntimeError, match="does not match the target instance ARN"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_drift_detected_when_state_changed_after_remediation(self) -> None:
        # GIVEN a snapshot (pre=0, post=60) but the instance is now at a different interval (15)
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_interval=0)
        _create_instance(monitoring_interval=15)
        with pytest.raises(RuntimeError, match="modified after the ASR remediation"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_monitoring_interval() == 15

    @mock_aws
    def test_role_drift_detected_when_only_role_changed(self) -> None:
        # GIVEN a snapshot (pre=0, post=60 + MONITORING_ROLE_ARN) but the instance's monitoring role was
        # changed after remediation while the interval still matches post (60). The role has drifted.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_interval=0)
        _create_instance(monitoring_interval=60)
        other_role = "arn:aws:iam::123456789012:role/other-monitoring-role"
        boto3.client("rds", config=BOTO_CONFIG).modify_db_instance(
            DBInstanceIdentifier=DB_INSTANCE_ID,
            MonitoringInterval=60,
            MonitoringRoleArn=other_role,
        )
        # WHEN execute_rollback runs THEN it aborts as drift (role differs from post) and does not restore.
        with pytest.raises(RuntimeError, match="modified after the ASR remediation"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_monitoring_role() == other_role

    @mock_aws
    def test_no_op_when_pre_equals_current(self) -> None:
        # GIVEN a snapshot where monitoring was already at 60 (+ its role) before remediation (pre == post)
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, pre_interval=60, pre_role=MONITORING_ROLE_ARN
        )
        _create_instance(monitoring_interval=60)
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_rerun_after_completed_rollback_is_idempotent(self) -> None:
        # GIVEN a genuine 0->60 remediation (pre=0, post=60) that has already been rolled back, so the
        # instance is back at the pre-remediation interval (0) — simulating an SSM step retry or an
        # operator re-running the rollback.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_interval=0)
        _create_instance(monitoring_interval=0)

        # WHEN execute_rollback runs again THEN it is a no-op success, NOT a drift failure: the no-op
        # (current == pre) check is evaluated before the post-remediation drift check.
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_monitoring_interval() == 0

    @mock_aws
    def test_schema_version_mismatch(self) -> None:
        # GIVEN a snapshot written under an incompatible schema version
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_interval=0, schema_version=999)
        _create_instance(monitoring_interval=60)
        with pytest.raises(RuntimeError, match="schema version mismatch"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_instance_not_found(self) -> None:
        # GIVEN a valid snapshot but the instance no longer exists
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_interval=0)
        with pytest.raises(RuntimeError, match="not found"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_malformed_snapshot_missing_state(self) -> None:
        # GIVEN a snapshot whose state objects lack the integer MonitoringInterval
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(
                {
                    "schemaVersion": 1,
                    "resourceId": RDS_INSTANCE_ARN,
                    "preRemediationState": {},
                    "postRemediationState": {},
                }
            ),
            ContentType="application/json",
        )
        _create_instance(monitoring_interval=60)
        with pytest.raises(RuntimeError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_corrupt_snapshot_raises_validation_error(self) -> None:
        # GIVEN a snapshot object whose body is not valid JSON (a data/validation problem, not I/O)
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body="not-json{{{",
            ContentType="application/json",
        )
        _create_instance(monitoring_interval=60)
        with pytest.raises(RuntimeError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_monitoring_interval() == 60


# ═══════════════════════════════════════════════════════════════
# handler (single dispatch entry point)
# ═══════════════════════════════════════════════════════════════


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(self) -> None:
        _create_snapshot_bucket()
        _create_instance(monitoring_interval=0)
        result = rollback.handler(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert _get_monitoring_interval() == 60

    @mock_aws
    def test_dispatches_to_execute_rollback(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_interval=0)
        _create_instance(monitoring_interval=60)
        event = {
            **_make_rollback_event(snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }
        result = rollback.handler(event, None)
        assert result["Status"] == "SUCCESS"
        assert "Successfully restored monitoring interval to 0" in result["Message"]
        assert result["snapshotStored"] == ""
        assert _get_monitoring_interval() == 0


# ═══════════════════════════════════════════════════════════════
# _wait_and_verify_state (post-remediation confirmation)
# ═══════════════════════════════════════════════════════════════


class TestWaitAndVerifyState:
    @mock_aws
    def test_passes_when_state_matches(self) -> None:
        # GIVEN an instance whose interval and role already match the expected values
        _create_instance(monitoring_interval=60)
        rds = boto3.client("rds", config=BOTO_CONFIG)
        # WHEN _wait_and_verify_state is called THEN it returns without raising
        rollback._wait_and_verify_state(
            rds, DB_INSTANCE_ID, expected_interval=60, expected_role=MONITORING_ROLE_ARN
        )

    @mock_aws
    def test_raises_when_state_mismatch(self, mocker) -> None:
        # GIVEN an instance whose interval never reaches the expected value (still disabled)
        mocker.patch.object(
            rollback, "_VERIFY_MAX_ATTEMPTS", 2
        )  # cap so the mismatch path doesn't sleep the full budget
        mocker.patch.object(rollback.time, "sleep")
        _create_instance(monitoring_interval=0)
        rds = boto3.client("rds", config=BOTO_CONFIG)
        # WHEN _wait_and_verify_state expects 60 THEN it raises after exhausting the poll budget
        with pytest.raises(RuntimeError, match="verification failed"):
            rollback._wait_and_verify_state(
                rds,
                DB_INSTANCE_ID,
                expected_interval=60,
                expected_role=MONITORING_ROLE_ARN,
            )

    @mock_aws
    def test_retries_until_state_settles(self, mocker) -> None:
        # Simulate the async race: the first poll reads stale state (interval 0), the second reads the applied
        # (60, role). moto applies ModifyDBInstance synchronously, so use a botocore Stubber to sequence two
        # real describe_db_instances responses — this exercises the real _get_monitoring_state code path
        # (rather than mocking our own function) and confirms the retry settles instead of failing on the stale read.
        mocker.patch.object(rollback.time, "sleep")
        rds = boto3.client("rds", config=BOTO_CONFIG)
        stubber = Stubber(rds)
        stale = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": DB_INSTANCE_ID,
                    "MonitoringInterval": 0,
                    "MonitoringRoleArn": "",
                }
            ]
        }
        applied = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": DB_INSTANCE_ID,
                    "MonitoringInterval": 60,
                    "MonitoringRoleArn": MONITORING_ROLE_ARN,
                }
            ]
        }
        stubber.add_response(
            "describe_db_instances", stale, {"DBInstanceIdentifier": DB_INSTANCE_ID}
        )
        stubber.add_response(
            "describe_db_instances", applied, {"DBInstanceIdentifier": DB_INSTANCE_ID}
        )
        with stubber:
            rollback._wait_and_verify_state(
                rds,
                DB_INSTANCE_ID,
                expected_interval=60,
                expected_role=MONITORING_ROLE_ARN,
            )
