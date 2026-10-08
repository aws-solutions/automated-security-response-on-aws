# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for RDS.16 — EnableCopyTagsToSnapshotOnRDSCluster rollback script.

moto implements RDS describe_db_clusters/modify_db_cluster (including CopyTagsToSnapshot), so these
tests use real moto-backed clients. The one exception spies on modify_db_cluster to assert the
ApplyImmediately arg (moto does not echo that request-only modifier back through describe).
"""
from __future__ import annotations

import json
from typing import Any

import boto3
import EnableCopyTagsToSnapshotOnRDSCluster_rollback as rollback
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from moto import mock_aws
from pytest_mock import MockerFixture

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "RDS.16"
ACCOUNT_ID = "123456789012"
CLUSTER_ID = "asr-test-cluster"
CLUSTER_ARN = "arn:aws:rds:us-east-1:123456789012:cluster:asr-test-cluster"


def _create_cluster(copy_tags: bool = False) -> None:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    rds.create_db_cluster(
        DBClusterIdentifier=CLUSTER_ID,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword="password1234",
        CopyTagsToSnapshot=copy_tags,
    )


def _get_copy_tags() -> bool:
    rds = boto3.client("rds", config=BOTO_CONFIG)
    return bool(
        rds.describe_db_clusters(DBClusterIdentifier=CLUSTER_ID)["DBClusters"][0].get(
            "CopyTagsToSnapshot", False
        )
    )


def _create_snapshot_bucket() -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=SNAPSHOT_BUCKET)
    s3.put_bucket_versioning(
        Bucket=SNAPSHOT_BUCKET, VersioningConfiguration={"Status": "Enabled"}
    )


def _put_snapshot(
    execution_id: str,
    pre_enabled: bool,
    post_enabled: bool = True,
    schema_version: int = 1,
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = f"snapshots/{execution_id}/{CONTROL_ID}.json"
    snapshot_data = {
        "schemaVersion": schema_version,
        "resourceId": CLUSTER_ARN,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"CopyTagsToSnapshot": pre_enabled},
        "postRemediationState": {"CopyTagsToSnapshot": post_enabled},
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
        "RDSClusterARN": CLUSTER_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
        "ApplyImmediately": True,
    }


def _make_rollback_event(
    execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, object]:
    return {
        "RDSClusterARN": CLUSTER_ARN,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": execution_id,
        "SnapshotVersionId": snapshot_version_id,
        "ApplyImmediately": True,
    }


def test_apply_immediately_false_reaches_modify(mocker: MockerFixture) -> None:
    # SSM passes InputPayload values as strings, so "false" must reach modify_db_cluster as the bool
    # False, not a truthy "false". Asserted through the public capture_and_remediate on the mutating
    # AWS call (per python-testing.md: assert on mutating calls to AWS services).
    with mock_aws():
        _create_snapshot_bucket()
        _create_cluster(copy_tags=False)
        rds = boto3.client("rds", config=BOTO_CONFIG)
        spy = mocker.spy(rds, "modify_db_cluster")
        original_client = boto3.client
        mocker.patch(
            "EnableCopyTagsToSnapshotOnRDSCluster_rollback.boto3.client",
            side_effect=lambda service, *a, **kw: (
                rds if service == "rds" else original_client(service, *a, **kw)
            ),
        )

        rollback.capture_and_remediate(
            {**_make_capture_event(), "ApplyImmediately": "false"}, None
        )

        assert spy.call_args.kwargs["ApplyImmediately"] is False


class TestCaptureAndRemediate:
    @mock_aws
    def test_successful_snapshot_and_remediation(self) -> None:
        _create_snapshot_bucket()
        _create_cluster(copy_tags=False)
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        assert "Disable CopyTagsToSnapshot" in result["rollbackDescription"]
        assert result["snapshotVersionId"] != ""
        assert _get_copy_tags() is True
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snap = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snap["preRemediationState"]["CopyTagsToSnapshot"] is False
        assert snap["postRemediationState"]["CopyTagsToSnapshot"] is True
        assert snap["resourceId"] == CLUSTER_ARN

    @mock_aws
    def test_no_op_when_already_enabled(self) -> None:
        # Already enabled (pre == post) -> no-op: no snapshot, no rollback offered, success.
        _create_snapshot_bucket()
        _create_cluster(copy_tags=True)
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "No remediation needed" in result["rollbackDescription"]
        assert _get_copy_tags() is True
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        objs = s3.list_objects_v2(
            Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
        )
        assert objs.get("KeyCount", 0) == 0

    @mock_aws
    def test_fail_open_when_bucket_missing(self) -> None:
        _create_cluster(copy_tags=False)
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="nonexistent-bucket"), None
        )
        assert result["snapshotStored"] == "false"
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert _get_copy_tags() is True

    @mock_aws
    def test_fail_open_when_bucket_not_provided(self) -> None:
        _create_cluster(copy_tags=False)
        result = rollback.capture_and_remediate(
            _make_capture_event(bucket="", execution_id=""), None
        )
        assert result["snapshotStored"] == "false"
        assert _get_copy_tags() is True

    def test_fail_open_when_pre_state_read_errors(self, mocker: MockerFixture) -> None:
        # A transient describe_db_clusters error must skip the snapshot (snapshotStored="false") but
        # NOT block the security remediation — the fail-open path in _read_pre_state. Asserted through
        # capture_and_remediate: modify_db_cluster still runs and enables CopyTagsToSnapshot.
        with mock_aws():
            _create_snapshot_bucket()
            _create_cluster(copy_tags=False)
            rds = boto3.client("rds", config=BOTO_CONFIG)
            # Fail only the first describe (the pre-state read); later describes (e.g. verification)
            # behave normally, so we can confirm remediation still applied.
            real_describe = rds.describe_db_clusters
            calls = {"n": 0}

            def describe_side_effect(**kwargs: Any) -> dict[str, Any]:
                calls["n"] += 1
                if calls["n"] == 1:
                    raise ClientError(
                        {"Error": {"Code": "InternalFailure", "Message": "transient"}},
                        "DescribeDBClusters",
                    )
                return real_describe(**kwargs)

            mocker.patch.object(
                rds, "describe_db_clusters", side_effect=describe_side_effect
            )
            original_client = boto3.client
            mocker.patch(
                "EnableCopyTagsToSnapshotOnRDSCluster_rollback.boto3.client",
                side_effect=lambda service, *a, **kw: (
                    rds if service == "rds" else original_client(service, *a, **kw)
                ),
            )

            result = rollback.capture_and_remediate(_make_capture_event(), None)

            assert result["snapshotStored"] == "false"
            assert "Rollback unavailable" in result["rollbackDescription"]
            # Remediation still applied despite the pre-state read failure.
            assert (
                rds.describe_db_clusters(DBClusterIdentifier=CLUSTER_ID)["DBClusters"][
                    0
                ]["CopyTagsToSnapshot"]
                is True
            )

    @mock_aws
    def test_non_string_bucket_treated_as_absent(self) -> None:
        _create_cluster(copy_tags=False)
        event = {**_make_capture_event(), "RemediationConfigBucket": None}
        result = rollback.capture_and_remediate(event, None)
        assert result["snapshotStored"] == "false"
        assert _get_copy_tags() is True

    @mock_aws
    def test_missing_cluster_arn_raises(self) -> None:
        event = {
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }
        with pytest.raises(ValueError, match="expected an RDS cluster ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_non_cluster_arn_rejected(self) -> None:
        # An RDS instance ARN (:db:) or other resource must not pass the :cluster: check.
        event = {
            **_make_capture_event(),
            "RDSClusterARN": "arn:aws:rds:us-east-1:123456789012:db:some-instance",
        }
        with pytest.raises(ValueError, match="expected an RDS cluster ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_cross_account_cluster_rejected(self) -> None:
        event = {
            **_make_capture_event(),
            "RDSClusterARN": "arn:aws:rds:us-east-1:999999999999:cluster:asr-test-cluster",
        }
        with pytest.raises(ValueError, match="does not match the executing account"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_invalid_account_id_rejected(self) -> None:
        event = {**_make_capture_event(), "AccountId": "123"}
        with pytest.raises(ValueError, match="expected 12-digit AWS account ID"):
            rollback.capture_and_remediate(event, None)


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_enabled=False)
        _create_cluster(copy_tags=True)  # currently in post-remediation state
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "Successfully restored" in result["Message"]
        assert _get_copy_tags() is False

    @mock_aws
    def test_missing_snapshot_version_id_raises(self) -> None:
        # Fail-closed: missing version id is a safety-gate failure (SnapshotValidationError), not a plain arg error.
        _create_snapshot_bucket()
        _put_snapshot(EXECUTION_ID, pre_enabled=False)
        _create_cluster(copy_tags=True)
        with pytest.raises(
            rollback.SnapshotValidationError,
            match="Missing required parameter: SnapshotVersionId",
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert _get_copy_tags() is True

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        _create_snapshot_bucket()
        _create_cluster(copy_tags=True)
        with pytest.raises(rollback.SnapshotNotFoundError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="missing-exec", snapshot_version_id="no-such-version"
                ),
                None,
            )
        assert _get_copy_tags() is True

    @mock_aws
    def test_idempotent_when_already_rolled_back(self) -> None:
        # pre=False, post=True, cluster currently False (== pre) -> idempotent no-op SUCCESS, not drift.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_enabled=False)
        _create_cluster(copy_tags=False)
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_copy_tags() is False

    @mock_aws
    def test_drift_abort_when_current_differs_from_post(self) -> None:
        # pre == post == enabled, but cluster currently disabled -> drift gate fires, cluster untouched.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_enabled=True, post_enabled=True)
        _create_cluster(copy_tags=False)
        with pytest.raises(
            rollback.SnapshotValidationError,
            match="does not match the post-remediation state",
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_copy_tags() is False

    @mock_aws
    def test_schema_version_mismatch(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_enabled=False, schema_version=999)
        _create_cluster(copy_tags=True)
        with pytest.raises(
            rollback.SnapshotValidationError, match="schema version mismatch"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _get_copy_tags() is True

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
        _create_cluster(copy_tags=True)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_copy_tags() is True

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
        _create_cluster(copy_tags=True)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=response["VersionId"]), None
            )
        assert _get_copy_tags() is True

    @mock_aws
    def test_cluster_not_found(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_enabled=False)
        # no cluster created
        with pytest.raises(rollback.ResourceNotFoundError, match="not found"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_missing_required_param_raises(self) -> None:
        _create_snapshot_bucket()
        _create_cluster(copy_tags=True)
        event = {
            "RDSClusterARN": CLUSTER_ARN,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v",
        }
        with pytest.raises(ValueError, match="Missing required parameter: AccountId"):
            rollback.execute_rollback(event, None)
        assert _get_copy_tags() is True


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(self) -> None:
        _create_snapshot_bucket()
        _create_cluster(copy_tags=False)
        result = rollback.handler(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert _get_copy_tags() is True

    @mock_aws
    def test_dispatches_to_execute_rollback(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_enabled=False)
        _create_cluster(copy_tags=True)
        event = {
            **_make_rollback_event(snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }
        result = rollback.handler(event, None)
        assert result["Status"] == "SUCCESS"
        assert result["snapshotStored"] == ""
        assert _get_copy_tags() is False

    @mock_aws
    def test_non_string_rollback_flag_dispatches_to_capture(self) -> None:
        _create_snapshot_bucket()
        _create_cluster(copy_tags=False)
        event = {**_make_capture_event(), "Rollback": None}
        result = rollback.handler(event, None)
        assert result["snapshotStored"] == "true"
        assert _get_copy_tags() is True
