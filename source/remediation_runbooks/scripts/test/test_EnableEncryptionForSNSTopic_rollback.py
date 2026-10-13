# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for SNS.1 — EnableEncryptionForSNSTopic rollback script."""
from __future__ import annotations

import json

import boto3
import EnableEncryptionForSNSTopic_rollback as rollback
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from moto import mock_aws
from pytest_mock import MockerFixture

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "SNS.1"
ACCOUNT_ID = "123456789012"
TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:asr-test-topic"
REMEDIATION_KEY = (
    "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
)
OTHER_KEY = (
    "arn:aws:kms:us-east-1:123456789012:key/99999999-8888-7777-6666-555555555555"
)


def _create_topic(kms_key: str = "") -> str:
    sns = boto3.client("sns", config=BOTO_CONFIG)
    arn = sns.create_topic(Name="asr-test-topic")["TopicArn"]
    if kms_key:
        sns.set_topic_attributes(
            TopicArn=arn, AttributeName="KmsMasterKeyId", AttributeValue=kms_key
        )
    return arn


def _get_key(topic_arn: str) -> str:
    sns = boto3.client("sns", config=BOTO_CONFIG)
    return sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"].get(
        "KmsMasterKeyId", ""
    )


def _create_snapshot_bucket() -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=SNAPSHOT_BUCKET)
    s3.put_bucket_versioning(
        Bucket=SNAPSHOT_BUCKET, VersioningConfiguration={"Status": "Enabled"}
    )


def _put_snapshot(
    execution_id: str,
    pre_key: str,
    post_key: str = REMEDIATION_KEY,
    schema_version: int = 1,
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = f"snapshots/{execution_id}/{CONTROL_ID}.json"
    snapshot_data = {
        "schemaVersion": schema_version,
        "resourceId": TOPIC_ARN,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"KmsMasterKeyId": pre_key},
        "postRemediationState": {"KmsMasterKeyId": post_key},
    }
    response = s3.put_object(
        Bucket=SNAPSHOT_BUCKET,
        Key=key,
        Body=json.dumps(snapshot_data),
        ContentType="application/json",
    )
    return response["VersionId"]


def _make_capture_event(
    topic_arn: str, bucket: str = SNAPSHOT_BUCKET, execution_id: str = EXECUTION_ID
) -> dict[str, str]:
    return {
        "TopicArn": topic_arn,
        "KmsKeyArn": REMEDIATION_KEY,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": bucket,
        "AutomationExecutionId": execution_id,
    }


def _make_rollback_event(
    topic_arn: str, execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, str]:
    return {
        "TopicArn": topic_arn,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": execution_id,
        "SnapshotVersionId": snapshot_version_id,
    }


def _patch_sns_client(mocker: MockerFixture, mock_sns: object) -> None:
    """Route the script's boto3.client("sns") to mock_sns; every other service falls through to the real
    (moto-backed) client. Encapsulates the selective-routing patch shared by the SNS read/write tests.
    """
    original_boto3_client = boto3.client
    mocker.patch(
        "EnableEncryptionForSNSTopic_rollback.boto3.client",
        side_effect=lambda service, *a, **kw: (
            mock_sns if service == "sns" else original_boto3_client(service, *a, **kw)
        ),
    )


# ═══════════════════════════════════════════════════════════════
# capture_and_remediate
# ═══════════════════════════════════════════════════════════════


class TestCaptureAndRemediate:
    @mock_aws
    def test_successful_snapshot_and_remediation(self) -> None:
        _create_snapshot_bucket()
        topic_arn = _create_topic(kms_key="")  # originally unencrypted

        result = rollback.capture_and_remediate(_make_capture_event(topic_arn), None)

        assert result["snapshotStored"] == "true"
        assert "unencrypted" in result["rollbackDescription"]
        assert result["snapshotVersionId"] != ""
        assert _get_key(topic_arn) == REMEDIATION_KEY

        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snapshot["preRemediationState"]["KmsMasterKeyId"] == ""
        assert snapshot["postRemediationState"]["KmsMasterKeyId"] == REMEDIATION_KEY
        assert snapshot["resourceId"] == topic_arn

    @mock_aws
    def test_remediates_topic_encrypted_with_different_key(self) -> None:
        # Realistic path: topic already encrypted with a DIFFERENT key -> ASR re-keys it to the ASR CMK.
        # Not a no-op (pre != post): snapshot captures OTHER_KEY as pre, REMEDIATION_KEY as post.
        _create_snapshot_bucket()
        topic_arn = _create_topic(kms_key=OTHER_KEY)

        result = rollback.capture_and_remediate(_make_capture_event(topic_arn), None)

        assert result["snapshotStored"] == "true"
        assert (
            OTHER_KEY in result["rollbackDescription"]
        )  # restore target is the original key
        assert _get_key(topic_arn) == REMEDIATION_KEY  # topic re-keyed to the ASR CMK

        s3 = boto3.client("s3", config=BOTO_CONFIG)
        snapshot = json.loads(
            s3.get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"].read()
        )
        assert snapshot["preRemediationState"]["KmsMasterKeyId"] == OTHER_KEY
        assert snapshot["postRemediationState"]["KmsMasterKeyId"] == REMEDIATION_KEY

    def test_ineffective_set_fails_remediation(self, mocker: MockerFixture) -> None:
        # Preserves the prior VerifyTopicEncryption guarantee: if set_topic_attributes silently does not
        # apply the key (rejected/ignored key, eventual consistency), the post-set verify read must fail
        # the remediation rather than report success.
        with mock_aws():
            _create_snapshot_bucket()
            topic_arn = _create_topic(
                kms_key=""
            )  # stays unencrypted because the set is a no-op
            real_sns = boto3.client("sns", config=BOTO_CONFIG)

            noop_sns = mocker.Mock(wraps=real_sns)
            noop_sns.set_topic_attributes.return_value = {}  # accepted but does nothing
            _patch_sns_client(mocker, noop_sns)

            with pytest.raises(RuntimeError, match="expected"):
                rollback.capture_and_remediate(_make_capture_event(topic_arn), None)

    @mock_aws
    def test_fail_open_when_bucket_missing(self) -> None:
        topic_arn = _create_topic(kms_key="")
        result = rollback.capture_and_remediate(
            _make_capture_event(topic_arn, bucket="nonexistent-bucket"), None
        )
        assert result["snapshotStored"] == "false"
        assert _get_key(topic_arn) == REMEDIATION_KEY

    @mock_aws
    def test_fail_open_when_bucket_not_provided(self) -> None:
        topic_arn = _create_topic(kms_key="")
        result = rollback.capture_and_remediate(
            _make_capture_event(topic_arn, bucket="", execution_id=""), None
        )
        assert result["snapshotStored"] == "false"
        assert _get_key(topic_arn) == REMEDIATION_KEY

    @mock_aws
    def test_non_string_bucket_treated_as_absent(self) -> None:
        topic_arn = _create_topic(kms_key="")
        event = {**_make_capture_event(topic_arn), "RemediationConfigBucket": None}
        result = rollback.capture_and_remediate(event, None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert _get_key(topic_arn) == REMEDIATION_KEY

    def test_fail_open_when_pre_state_read_errors(self, mocker: MockerFixture) -> None:
        # A GetTopicAttributes failure on the pre-state read must skip the snapshot (snapshotStored="false")
        # but still apply the remediation (fail-open contract), matching the bucket-missing paths above.
        # Mocked at the boto3 boundary (SNS get_topic_attributes) — not the module's own _get_kms_key — so
        # the real _get_kms_key -> _read_pre_state error path is exercised.
        with mock_aws():
            _create_snapshot_bucket()
            topic_arn = _create_topic(kms_key="")
            real_sns = boto3.client("sns", config=BOTO_CONFIG)

            # Stub only get_topic_attributes to fail; every other call (set_topic_attributes, the S3
            # verification read below) goes to the real moto client.
            failing_sns = mocker.Mock(wraps=real_sns)
            # Fail only the FIRST get_topic_attributes (the pre-state read); later calls (the post-set
            # verification read) delegate to the real client, so we exercise the fail-open pre-state path
            # without breaking the remediation's verify step.
            call_count = {"n": 0}

            def get_attrs(*args: object, **kwargs: object) -> object:
                call_count["n"] += 1
                if call_count["n"] == 1:
                    raise ClientError(
                        {"Error": {"Code": "AuthorizationError"}}, "GetTopicAttributes"
                    )
                return real_sns.get_topic_attributes(*args, **kwargs)  # type: ignore[arg-type]

            failing_sns.get_topic_attributes.side_effect = get_attrs
            _patch_sns_client(mocker, failing_sns)

            result = rollback.capture_and_remediate(
                _make_capture_event(topic_arn), None
            )

            assert result["snapshotStored"] == "false"
            assert "Rollback unavailable" in result["rollbackDescription"]
            # Remediation still applied despite the pre-state read failure. Verify via real_sns (the
            # patched boto3.client would hand back the failing stub).
            applied = real_sns.get_topic_attributes(TopicArn=topic_arn)[
                "Attributes"
            ].get("KmsMasterKeyId", "")
            assert applied == REMEDIATION_KEY

    @mock_aws
    def test_unversioned_bucket_reports_not_rollback_able(self) -> None:
        # write_snapshot returns no version id when the bucket has versioning disabled. Rollback reads the
        # exact captured version and fails closed on an empty id, so a snapshot with no version id must be
        # reported as not stored / rollback unavailable — not as a restore-able snapshot.
        boto3.client("s3", config=BOTO_CONFIG).create_bucket(
            Bucket=SNAPSHOT_BUCKET
        )  # no versioning
        topic_arn = _create_topic(kms_key="")

        result = rollback.capture_and_remediate(_make_capture_event(topic_arn), None)

        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "Rollback unavailable" in result["rollbackDescription"]
        # Remediation still applied.
        assert _get_key(topic_arn) == REMEDIATION_KEY

    @mock_aws
    def test_no_op_when_already_encrypted_with_remediation_key(self) -> None:
        # Topic already encrypted with the exact ASR CMK (pre == post) -> no-op: no snapshot written,
        # no rollback offered, success. (Prevents a misleading no-op rollback snapshot.)
        _create_snapshot_bucket()
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
        result = rollback.capture_and_remediate(_make_capture_event(topic_arn), None)
        assert result["snapshotStored"] == "false"
        assert result["snapshotVersionId"] == ""
        assert "No remediation needed" in result["rollbackDescription"]
        assert _get_key(topic_arn) == REMEDIATION_KEY
        # and no snapshot object was written
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        object_listing = s3.list_objects_v2(
            Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
        )
        assert object_listing.get("KeyCount", 0) == 0

    @mock_aws
    def test_missing_topic_arn_raises(self) -> None:
        event = {
            "KmsKeyArn": REMEDIATION_KEY,
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }
        with pytest.raises(ValueError, match="expected an SNS topic ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_non_arn_with_sns_marker_raises(self) -> None:
        event = {**_make_capture_event(TOPIC_ARN), "TopicArn": "foo:sns:bar"}
        with pytest.raises(ValueError, match="expected an SNS topic ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_lookalike_arn_with_embedded_sns_rejected(self) -> None:
        # An ARN of another service whose resource happens to contain ':sns:' must NOT pass the
        # structural validator (6-segment parse pins service to segment 2).
        event = {
            **_make_capture_event(TOPIC_ARN),
            "TopicArn": "arn:aws:iam::123456789012:role/x:sns:y",
        }
        with pytest.raises(ValueError, match="expected an SNS topic ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_cross_account_topic_rejected(self) -> None:
        # TopicArn in a different account than the executing account (AccountId) is refused.
        cross = "arn:aws:sns:us-east-1:999999999999:asr-test-topic"
        event = {**_make_capture_event(TOPIC_ARN), "TopicArn": cross}
        with pytest.raises(ValueError, match="does not match the executing account"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_malformed_kms_key_arn_rejected(self) -> None:
        # A non-ARN / wrong-service KmsKeyArn is refused before it can be set as the topic key.
        event = {**_make_capture_event(TOPIC_ARN), "KmsKeyArn": "not-a-key"}
        with pytest.raises(ValueError, match="expected a KMS key ARN"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_invalid_account_id_rejected(self) -> None:
        # A non-12-digit AccountId gives a clear error here, not a confusing cross-account mismatch.
        event = {**_make_capture_event(TOPIC_ARN), "AccountId": "123"}
        with pytest.raises(ValueError, match="expected 12-digit AWS account ID"):
            rollback.capture_and_remediate(event, None)

    @mock_aws
    def test_missing_kms_key_raises(self) -> None:
        _create_topic(kms_key="")
        event = {
            "TopicArn": TOPIC_ARN,
            "AccountId": ACCOUNT_ID,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "AutomationExecutionId": EXECUTION_ID,
        }
        with pytest.raises(ValueError, match="required parameter: KmsKeyArn"):
            rollback.capture_and_remediate(event, None)


# ═══════════════════════════════════════════════════════════════
# execute_rollback
# ═══════════════════════════════════════════════════════════════


class TestExecuteRollback:
    @mock_aws
    def test_successful_restore_clears_encryption(self) -> None:
        # Primary path: originally unencrypted -> rollback clears the key back to "".
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_key="")
        topic_arn = _create_topic(
            kms_key=REMEDIATION_KEY
        )  # currently in post-remediation state

        result = rollback.execute_rollback(
            _make_rollback_event(topic_arn, snapshot_version_id=version_id), None
        )

        assert result["Status"] == "SUCCESS"
        assert "Successfully restored" in result["Message"]
        assert _get_key(topic_arn) == ""  # encryption cleared (back to unencrypted)

    @mock_aws
    def test_restore_to_original_key_when_pre_was_a_key(self) -> None:
        # Defensive (not reachable via normal finding flow): pre had a different key -> restore it exactly.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_key=OTHER_KEY)
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)

        result = rollback.execute_rollback(
            _make_rollback_event(topic_arn, snapshot_version_id=version_id), None
        )

        assert result["Status"] == "SUCCESS"
        assert _get_key(topic_arn) == OTHER_KEY

    @mock_aws
    def test_missing_snapshot_version_id_raises(self) -> None:
        # Fail-closed: missing version id is a safety-gate failure (SnapshotValidationError), not a plain arg error.
        _create_snapshot_bucket()
        _put_snapshot(EXECUTION_ID, pre_key="")
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
        with pytest.raises(
            rollback.SnapshotValidationError,
            match="Missing required parameter: SnapshotVersionId",
        ):
            rollback.execute_rollback(
                _make_rollback_event(topic_arn, snapshot_version_id=""), None
            )
        assert _get_key(topic_arn) == REMEDIATION_KEY

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        _create_snapshot_bucket()
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
        with pytest.raises(rollback.SnapshotNotFoundError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    topic_arn,
                    execution_id="missing-exec",
                    snapshot_version_id="no-such-version",
                ),
                None,
            )
        assert _get_key(topic_arn) == REMEDIATION_KEY

    @mock_aws
    def test_drift_detected_when_state_changed_after_remediation(self) -> None:
        # Snapshot post=REMEDIATION_KEY but the topic now has a different key -> drift -> abort.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_key="")
        topic_arn = _create_topic(
            kms_key=OTHER_KEY
        )  # someone changed it after remediation
        with pytest.raises(
            rollback.SnapshotValidationError, match="modified after the ASR remediation"
        ):
            rollback.execute_rollback(
                _make_rollback_event(topic_arn, snapshot_version_id=version_id), None
            )
        assert _get_key(topic_arn) == OTHER_KEY

    @mock_aws
    def test_no_op_when_pre_equals_current(self) -> None:
        # pre == post == current (topic already at the "post" key AND that equals pre) -> no-op success.
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, pre_key=REMEDIATION_KEY, post_key=REMEDIATION_KEY
        )
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
        result = rollback.execute_rollback(
            _make_rollback_event(topic_arn, snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_key(topic_arn) == REMEDIATION_KEY

    @mock_aws
    def test_idempotent_when_already_rolled_back(self) -> None:
        # Realistic idempotency: pre != post (real remediation) and the topic is already back at pre
        # (e.g. a second rollback). The no-op gate must return SUCCESS, NOT the drift error — the
        # no-op check runs before the drift gate.
        _create_snapshot_bucket()
        version_id = _put_snapshot(
            EXECUTION_ID, pre_key=""
        )  # pre="" != post=REMEDIATION_KEY
        topic_arn = _create_topic(kms_key="")  # current == pre (already unencrypted)
        result = rollback.execute_rollback(
            _make_rollback_event(topic_arn, snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_key(topic_arn) == ""

    @mock_aws
    def test_schema_version_mismatch(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_key="", schema_version=999)
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
        with pytest.raises(
            rollback.SnapshotValidationError, match="schema version mismatch"
        ):
            rollback.execute_rollback(
                _make_rollback_event(topic_arn, snapshot_version_id=version_id), None
            )
        assert _get_key(topic_arn) == REMEDIATION_KEY

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
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(
                    topic_arn, snapshot_version_id=response["VersionId"]
                ),
                None,
            )
        assert _get_key(topic_arn) == REMEDIATION_KEY

    @mock_aws
    def test_corrupt_snapshot_raises_validation_error(self) -> None:
        # Corrupt / non-JSON snapshot content is a validation problem (malformed), not an I/O read error.
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        response = s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body="not-json{{{",
            ContentType="application/json",
        )
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
        with pytest.raises(rollback.SnapshotValidationError, match="malformed"):
            rollback.execute_rollback(
                _make_rollback_event(
                    topic_arn, snapshot_version_id=response["VersionId"]
                ),
                None,
            )
        assert _get_key(topic_arn) == REMEDIATION_KEY

    @mock_aws
    def test_current_state_read_deleted_topic_raises_resource_not_found(self) -> None:
        # Fail-closed: if the topic was deleted between remediation and rollback, the current-state read
        # surfaces a classified ResourceNotFoundError (a RollbackError), not a raw botocore exception.
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_key="")
        # No topic created -> GetTopicAttributes on a nonexistent topic raises NotFoundException.
        with pytest.raises(rollback.ResourceNotFoundError, match="not found"):
            rollback.execute_rollback(
                _make_rollback_event(TOPIC_ARN, snapshot_version_id=version_id), None
            )

    def test_current_state_read_error_wrapped_as_rollback_error(
        self, mocker: MockerFixture
    ) -> None:
        # Fail-closed: a non-not-found read failure (e.g. access denied) on the current-state read is
        # wrapped as SnapshotReadError so every rollback failure surfaces as a classified RollbackError.
        with mock_aws():
            _create_snapshot_bucket()
            version_id = _put_snapshot(EXECUTION_ID, pre_key="")
            topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
            real_sns = boto3.client("sns", config=BOTO_CONFIG)

            failing_sns = mocker.Mock(wraps=real_sns)
            failing_sns.get_topic_attributes.side_effect = ClientError(
                {"Error": {"Code": "AuthorizationError"}}, "GetTopicAttributes"
            )
            _patch_sns_client(mocker, failing_sns)

            with pytest.raises(
                rollback.SnapshotReadError, match="Failed to read current state"
            ):
                rollback.execute_rollback(
                    _make_rollback_event(topic_arn, snapshot_version_id=version_id),
                    None,
                )

    def test_restore_write_failure_wrapped_as_rollback_error(
        self, mocker: MockerFixture
    ) -> None:
        # Fail-closed TOCTOU guard: if set_topic_attributes fails after the drift check passes (e.g. the
        # topic is deleted between the current-state read and the restore write), the failure must surface
        # as a classified RollbackError, not a raw botocore exception.
        with mock_aws():
            _create_snapshot_bucket()
            version_id = _put_snapshot(
                EXECUTION_ID, pre_key=""
            )  # pre="" != post=REMEDIATION_KEY
            topic_arn = _create_topic(
                kms_key=REMEDIATION_KEY
            )  # current == post -> drift check passes -> RESTORE
            real_sns = boto3.client("sns", config=BOTO_CONFIG)

            # get_topic_attributes (current-state read) works; only the restore set_topic_attributes fails.
            failing_sns = mocker.Mock(wraps=real_sns)
            failing_sns.set_topic_attributes.side_effect = ClientError(
                {"Error": {"Code": "NotFound"}}, "SetTopicAttributes"
            )
            _patch_sns_client(mocker, failing_sns)

            with pytest.raises(
                rollback.ResourceNotFoundError,
                match="not found during rollback restore",
            ):
                rollback.execute_rollback(
                    _make_rollback_event(topic_arn, snapshot_version_id=version_id),
                    None,
                )

    def test_restore_write_non_notfound_error_wrapped_as_rollback_error(
        self, mocker: MockerFixture
    ) -> None:
        # A non-not-found restore-write failure (e.g. throttle/access denied) surfaces as the base
        # RollbackError so it still marks the SSM step Failed per the fail-closed contract.
        with mock_aws():
            _create_snapshot_bucket()
            version_id = _put_snapshot(EXECUTION_ID, pre_key="")
            topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
            real_sns = boto3.client("sns", config=BOTO_CONFIG)

            failing_sns = mocker.Mock(wraps=real_sns)
            failing_sns.set_topic_attributes.side_effect = ClientError(
                {"Error": {"Code": "ThrottlingException"}}, "SetTopicAttributes"
            )
            _patch_sns_client(mocker, failing_sns)

            with pytest.raises(
                rollback.RollbackError, match="Failed to restore KmsMasterKeyId"
            ):
                rollback.execute_rollback(
                    _make_rollback_event(topic_arn, snapshot_version_id=version_id),
                    None,
                )

    def test_ineffective_restore_fails_rollback(self, mocker: MockerFixture) -> None:
        # Fail-closed symmetry with the remediation path: if the restore set_topic_attributes is silently
        # ineffective (accepted but does not apply), the post-restore verify must raise RollbackError rather
        # than report a successful rollback while the topic stays in the post-remediation state.
        with mock_aws():
            _create_snapshot_bucket()
            version_id = _put_snapshot(
                EXECUTION_ID, pre_key=""
            )  # restore target "" (unencrypted)
            topic_arn = _create_topic(
                kms_key=REMEDIATION_KEY
            )  # current == post -> drift passes -> RESTORE
            real_sns = boto3.client("sns", config=BOTO_CONFIG)

            # get_topic_attributes works (so the current-state read + verify read reflect the real, still
            # post-remediation topic); set_topic_attributes is accepted but does nothing.
            noop_sns = mocker.Mock(wraps=real_sns)
            noop_sns.set_topic_attributes.return_value = {}
            _patch_sns_client(mocker, noop_sns)

            with pytest.raises(rollback.RollbackError, match="expected"):
                rollback.execute_rollback(
                    _make_rollback_event(topic_arn, snapshot_version_id=version_id),
                    None,
                )

    @mock_aws
    def test_missing_required_param_raises(self) -> None:
        _create_snapshot_bucket()
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
        event = {
            "TopicArn": topic_arn,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v",
        }
        with pytest.raises(ValueError, match="Missing required parameter: AccountId"):
            rollback.execute_rollback(event, None)
        assert _get_key(topic_arn) == REMEDIATION_KEY


# ═══════════════════════════════════════════════════════════════
# handler (single dispatch entry point)
# ═══════════════════════════════════════════════════════════════


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(self) -> None:
        _create_snapshot_bucket()
        topic_arn = _create_topic(kms_key="")
        result = rollback.handler(_make_capture_event(topic_arn), None)
        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert _get_key(topic_arn) == REMEDIATION_KEY

    @mock_aws
    def test_dispatches_to_execute_rollback(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(EXECUTION_ID, pre_key="")
        topic_arn = _create_topic(kms_key=REMEDIATION_KEY)
        event = {
            **_make_rollback_event(topic_arn, snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }
        result = rollback.handler(event, None)
        assert result["Status"] == "SUCCESS"
        assert result["snapshotStored"] == ""
        assert _get_key(topic_arn) == ""

    @mock_aws
    def test_non_string_rollback_flag_dispatches_to_capture(self) -> None:
        # A non-string Rollback (e.g. None) must NOT be coerced to "None" and mis-routed; it falls
        # through to the capture path (isinstance guard at the boundary).
        _create_snapshot_bucket()
        topic_arn = _create_topic(kms_key="")
        event = {**_make_capture_event(topic_arn), "Rollback": None}
        result = rollback.handler(event, None)
        assert result["snapshotStored"] == "true"  # capture path ran
        assert result["Status"] == ""
        assert _get_key(topic_arn) == REMEDIATION_KEY
