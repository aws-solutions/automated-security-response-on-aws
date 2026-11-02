# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for S3.6 — PutS3BucketPolicyDeny rollback script.

moto implements S3 get/put/delete_bucket_policy, so these tests use real moto-backed clients. State for
the drift check is the ASR deny statement (Sid=ASR-S3.6-DenyCrossAccountAccess); rollback removes only
that statement, preserving other statements in the current policy.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import boto3
import PutS3BucketPolicyDeny_rollback as rollback
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from common.snapshot_utils import (  # noqa: E402
    ResourceNotFoundError,
    RollbackError,
    SnapshotNotFoundError,
    SnapshotValidationError,
)
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
SNAPSHOT_BUCKET = "asr-remediation-config-bucket"
EXECUTION_ID = "exec-abc123-test"
CONTROL_ID = "S3.6"
ACCOUNT_ID = "123456789012"
BUCKET = "asr-test-bucket"
PARTITION = "aws"
OTHER_ACCOUNT = "999999999999"
CROSS_ACCOUNT_PRINCIPAL = f"arn:aws:iam::{OTHER_ACCOUNT}:root"
DENYLIST = "s3:PutBucketAcl,s3:PutBucketPolicy"
ASR_SID = rollback.ASR_SID

ALLOW_CROSS_ACCOUNT_STATEMENT = {
    "Sid": "AllowOtherAccount",
    "Effect": "Allow",
    "Principal": {"AWS": CROSS_ACCOUNT_PRINCIPAL},
    "Action": "s3:GetObject",
    "Resource": f"arn:aws:s3:::{BUCKET}/*",
}


NEW_CROSS_ACCOUNT_PRINCIPAL = "arn:aws:iam::888888888888:root"
NEW_CROSS_ACCOUNT_STATEMENT = {
    "Sid": "AllowNewAccount",
    "Effect": "Allow",
    "Principal": {"AWS": NEW_CROSS_ACCOUNT_PRINCIPAL},
    "Action": ["s3:GetObject", "s3:PutBucketPolicy"],
    "Resource": f"arn:aws:s3:::{BUCKET}/*",
}


def _create_bucket(statements: list[dict[str, Any]] | None = None) -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=BUCKET)
    if statements is not None:
        s3.put_bucket_policy(
            Bucket=BUCKET,
            Policy=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )


def _get_policy() -> dict[str, Any] | None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    try:
        return json.loads(s3.get_bucket_policy(Bucket=BUCKET)["Policy"])
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in (
            "NoSuchBucketPolicy",
            "NoSuchBucket",
        ):
            return None
        raise


def _require_policy() -> dict[str, Any]:
    policy = _get_policy()
    assert policy is not None, "expected a bucket policy to exist"
    return policy


def _asr_statement(policy: dict[str, Any] | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    for s in policy.get("Statement", []):
        if isinstance(s, dict) and s.get("Sid") == ASR_SID:
            return s
    return None


# Edits that keep the statement a Deny but stop it denying unconditionally on the whole bucket.
NARROWED_DENY_TAMPERS = [
    pytest.param(
        {
            "Resource": [
                f"arn:aws:s3:::{BUCKET}",
                f"arn:aws:s3:::{BUCKET}/no-such-prefix/*",
            ]
        },
        id="narrowed-object-resource",
    ),
    pytest.param(
        {"Condition": {"StringEquals": {"aws:SourceVpce": "vpce-never"}}},
        id="never-matching-condition",
    ),
]
NEUTERING_TAMPERS = [
    pytest.param({"Effect": "Allow"}, id="effect-allow"),
    *NARROWED_DENY_TAMPERS,
]


def _latest_snapshot_version_id() -> str:
    """Version id of the newest snapshot object for this test's execution."""
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    versions = s3.list_object_versions(
        Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
    ).get("Versions", [])
    latest = [version for version in versions if version.get("IsLatest")]
    return latest[0]["VersionId"] if latest else ""


def _create_snapshot_bucket() -> None:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    s3.create_bucket(Bucket=SNAPSHOT_BUCKET)
    s3.put_bucket_versioning(
        Bucket=SNAPSHOT_BUCKET, VersioningConfiguration={"Status": "Enabled"}
    )


def _built_asr_statement(
    principals: list[str] | None = None, actions: list[str] | None = None
) -> dict[str, Any]:
    return dict(
        rollback._build_deny_statement(
            principals=(
                principals if principals is not None else [CROSS_ACCOUNT_PRINCIPAL]
            ),
            actions=(
                actions
                if actions is not None
                else ["s3:PutBucketAcl", "s3:PutBucketPolicy"]
            ),
            bucket=BUCKET,
            partition=PARTITION,
        )
    )


def _put_snapshot(
    execution_id: str = EXECUTION_ID,
    *,
    pre_policy: str | None = None,
    post_asr_statement: dict[str, Any] | None = None,
    schema_version: int = 1,
    resource_id: str = BUCKET,
    omit_asr: bool = False,
) -> str:
    s3 = boto3.client("s3", config=BOTO_CONFIG)
    key = f"snapshots/{execution_id}/{CONTROL_ID}.json"
    post_state: dict[str, Any] = (
        {}
        if omit_asr
        else {"AsrStatement": post_asr_statement or _built_asr_statement()}
    )
    data = {
        "schemaVersion": schema_version,
        "resourceId": resource_id,
        "controlId": CONTROL_ID,
        "capturedAt": "2025-01-01T00:00:00+00:00",
        "preRemediationState": {"BucketPolicy": pre_policy},
        "postRemediationState": post_state,
    }
    return str(
        s3.put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=key,
            Body=json.dumps(data),
            ContentType="application/json",
        )["VersionId"]
    )


class _FrozenPolicyReadS3:
    """Delegates to the real moto client but pins get_bucket_policy to the policy given at construction.

    Simulates a write that silently does not take effect (or a stale read-back), which is the only way to
    reach the post-write verification branches: moto stores what it is given, so a real read-back always
    agrees with the write. Only the S3 boundary is stubbed; the script's own logic runs unchanged.
    """

    def __init__(self, client: rollback.S3Client, frozen_policy: str) -> None:
        self._client = client
        self._frozen_policy = frozen_policy

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def get_bucket_policy(self, **_kwargs: Any) -> dict[str, Any]:
        return {"Policy": self._frozen_policy}


def _freeze_policy_reads(
    monkeypatch: pytest.MonkeyPatch, frozen_policy: dict[str, Any]
) -> None:
    original_client = rollback.boto3.client
    frozen_json = json.dumps(frozen_policy)

    def _client(service_name: str, *args: Any, **kwargs: Any) -> Any:
        client = original_client(service_name, *args, **kwargs)
        return (
            _FrozenPolicyReadS3(client, frozen_json) if service_name == "s3" else client
        )

    monkeypatch.setattr(rollback.boto3, "client", _client)


class _StalePolicyReadS3:
    """Delegates to the real moto client, but the first `stale_calls` policy reads return a stale policy.

    Models the documented bucket-subresource lag: S3's strong read-after-write consistency covers objects,
    not bucket configuration, so the first read-back after PutBucketPolicy can still show the old policy.
    """

    def __init__(
        self, client: rollback.S3Client, stale_policy: str, stale_calls: int
    ) -> None:
        self._client = client
        self._stale_policy = stale_policy
        self._remaining_stale = stale_calls

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    def get_bucket_policy(self, **kwargs: Any) -> dict[str, Any]:
        if self._remaining_stale > 0:
            self._remaining_stale -= 1
            return {"Policy": self._stale_policy}
        return dict(self._client.get_bucket_policy(**kwargs))


def _stale_policy_reads(
    monkeypatch: pytest.MonkeyPatch, stale_policy: dict[str, Any], stale_calls: int
) -> None:
    original_client = rollback.boto3.client
    stale_json = json.dumps(stale_policy)

    def _client(service_name: str, *args: Any, **kwargs: Any) -> Any:
        client = original_client(service_name, *args, **kwargs)
        return (
            _StalePolicyReadS3(client, stale_json, stale_calls)
            if service_name == "s3"
            else client
        )

    monkeypatch.setattr(rollback.boto3, "client", _client)


def _make_capture_event(
    *, config_bucket: str = SNAPSHOT_BUCKET, execution_id: str = EXECUTION_ID
) -> dict[str, object]:
    return {
        "BucketName": BUCKET,
        "AccountId": ACCOUNT_ID,
        "Partition": PARTITION,
        "DenyList": DENYLIST,
        "RemediationConfigBucket": config_bucket,
        "AutomationExecutionId": execution_id,
    }


def _make_rollback_event(
    *, execution_id: str = EXECUTION_ID, snapshot_version_id: str = ""
) -> dict[str, object]:
    return {
        "BucketName": BUCKET,
        "AccountId": ACCOUNT_ID,
        "RemediationConfigBucket": SNAPSHOT_BUCKET,
        "ExecutionId": execution_id,
        "SnapshotVersionId": snapshot_version_id,
    }


# ── unit: validation / helpers ───────────────────────────────────────────────


def test_collect_principals_skips_wildcard_aws_principal() -> None:
    # Principal {"AWS": "*"} must yield no principals: a Deny naming "*" would lock every caller out of the
    # bucket, and the wildcard grant is not a cross-account grant to a specific account. The superseded
    # script crashed here with IndexError (it indexed segment 4 of a non-ARN unconditionally).
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject"}
        ],
    }
    assert rollback._collect_cross_account_principals(policy, ACCOUNT_ID) == []


def test_collect_principals_accepts_bare_account_id() -> None:
    # A principal may be a bare 12-digit account id rather than a full ARN. The bucket owner's own id is
    # still excluded, since only cross-account grants are denied.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": OTHER_ACCOUNT},
                "Action": "s3:GetObject",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": ACCOUNT_ID},
                "Action": "s3:GetObject",
            },
        ],
    }
    assert rollback._collect_cross_account_principals(policy, ACCOUNT_ID) == [
        OTHER_ACCOUNT
    ]


def test_collect_principals_skips_statements_without_aws_principals() -> None:
    # A service principal is not an account principal, so there is nothing cross-account to deny.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
            },
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"},
            {"Effect": "Allow", "Action": "s3:GetObject"},
        ],
    }
    assert rollback._collect_cross_account_principals(policy, ACCOUNT_ID) == []


def test_collect_principals_multiple_principals_ordered_and_deduped() -> None:
    third_account = "444455556666"
    third_principal = f"arn:aws:iam::{third_account}:role/reader"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        CROSS_ACCOUNT_PRINCIPAL,
                        third_principal,
                        CROSS_ACCOUNT_PRINCIPAL,
                    ]
                },
                "Action": "s3:GetObject",
            },
            # Same-account principal and a repeat of an already-collected one add nothing.
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                "Action": "s3:GetObject",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": third_principal},
                "Action": "s3:PutObject",
            },
        ],
    }
    assert rollback._collect_cross_account_principals(policy, ACCOUNT_ID) == [
        CROSS_ACCOUNT_PRINCIPAL,
        third_principal,
    ]


def test_validate_denylist_parses_and_dedups() -> None:
    assert rollback._validate_denylist(
        {"DenyList": "s3:PutBucketAcl, s3:PutBucketPolicy ,s3:PutBucketAcl"}
    ) == [
        "s3:PutBucketAcl",
        "s3:PutBucketPolicy",
    ]


def test_validate_denylist_empty_raises() -> None:
    with pytest.raises(ValueError, match="DenyList"):
        rollback._validate_denylist({"DenyList": "  ,  "})


def test_validate_account_id_rejects_unicode_digits() -> None:
    # str.isdigit() accepts full-width/superscript digits, which are not valid AWS account IDs.
    with pytest.raises(ValueError, match="12-digit"):
        rollback._validate_account_id(
            {
                "AccountId": "\uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff18\uff19\uff10\uff11\uff12"
            }
        )


def test_validate_partition_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="Partition"):
        rollback._validate_partition({"Partition": "aws-mars"})


def test_collect_cross_account_principals_skips_same_account_and_wildcard() -> None:
    policy = {
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"},
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                "Action": "s3:GetObject",
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": [CROSS_ACCOUNT_PRINCIPAL, CROSS_ACCOUNT_PRINCIPAL]
                },
                "Action": "s3:GetObject",
            },
        ]
    }
    assert rollback._collect_cross_account_principals(policy, ACCOUNT_ID) == [
        CROSS_ACCOUNT_PRINCIPAL
    ]


def test_normalize_is_order_insensitive() -> None:
    a = {"Sid": ASR_SID, "Principal": {"AWS": ["arn:b", "arn:a"]}, "Action": ["y", "x"]}
    b = {"Action": ["x", "y"], "Principal": {"AWS": ["arn:a", "arn:b"]}, "Sid": ASR_SID}
    assert rollback._normalize(a) == rollback._normalize(b)
    assert rollback._normalize(None) == ""


def test_normalize_treats_single_element_list_as_scalar() -> None:
    # S3 canonicalizes a single-element array into a scalar on read-back; the drift check must treat the
    # stored (list) and live (scalar) forms as equal so a single-principal/single-action deny isn't false drift.
    stored = {
        "Sid": ASR_SID,
        "Effect": "Deny",
        "Principal": {"AWS": [CROSS_ACCOUNT_PRINCIPAL]},
        "Action": ["s3:PutBucketAcl"],
    }
    live = {
        "Sid": ASR_SID,
        "Effect": "Deny",
        "Principal": {"AWS": CROSS_ACCOUNT_PRINCIPAL},
        "Action": "s3:PutBucketAcl",
    }
    assert rollback._normalize(stored) == rollback._normalize(live)


# ── capture_and_remediate ────────────────────────────────────────────────────


def test_unconditional_bucket_deny_accepts_the_s3_read_back_form() -> None:
    written = _built_asr_statement()
    read_back = {**written, "Principal": {"AWS": written["Principal"]["AWS"][0]}}
    assert rollback._is_unconditional_bucket_deny(
        read_back, bucket=BUCKET, partition=PARTITION
    )


@pytest.mark.parametrize("tamper", [*NEUTERING_TAMPERS, {"Principal": "*"}])
def test_unconditional_bucket_deny_rejects_other_statements(
    tamper: dict[str, Any],
) -> None:
    statement = {**_built_asr_statement(), **tamper}
    assert not rollback._is_unconditional_bucket_deny(
        statement, bucket=BUCKET, partition=PARTITION
    )


class TestCaptureAndRemediate:
    @mock_aws
    def test_stale_read_back_is_retried_and_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The policy did apply but the first read-back is stale. The retry must see it and report success,
        # because failing here would also discard the snapshot version id and the bucket's one-click rollback.
        _create_snapshot_bucket()
        original_policy = {
            "Version": "2012-10-17",
            "Statement": [ALLOW_CROSS_ACCOUNT_STATEMENT],
        }
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT])
        # Call 1 is the pre-remediation read, call 2 is the first (stale) verification read.
        _stale_policy_reads(monkeypatch, original_policy, stale_calls=2)
        monkeypatch.setattr(rollback.time, "sleep", lambda _seconds: None)
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        # Undo the patch first: it also intercepts this test's own client, which would serve a stale read.
        monkeypatch.undo()
        assert _asr_statement(_require_policy()) is not None

    @mock_aws
    def test_verification_failure_when_deny_statement_does_not_persist(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The put succeeds but the read-back does not show the ASR statement, so the remediation must fail
        # loudly rather than report success on a bucket that is still unrestricted.
        _create_snapshot_bucket()
        original_policy = {
            "Version": "2012-10-17",
            "Statement": [ALLOW_CROSS_ACCOUNT_STATEMENT],
        }
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT])
        _freeze_policy_reads(monkeypatch, original_policy)
        monkeypatch.setattr(
            rollback.time, "sleep", lambda _seconds: None
        )  # don't wait out the real backoff
        with pytest.raises(rollback.RemediationError, match="Verification failed"):
            rollback.capture_and_remediate(_make_capture_event(), None)

    @mock_aws
    def test_verification_failure_reports_snapshot_version_for_manual_rollback(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _create_snapshot_bucket()
        original_policy = {
            "Version": "2012-10-17",
            "Statement": [ALLOW_CROSS_ACCOUNT_STATEMENT],
        }
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT])
        _freeze_policy_reads(monkeypatch, original_policy)
        monkeypatch.setattr(rollback.time, "sleep", lambda _seconds: None)

        with caplog.at_level(logging.ERROR, logger=rollback.logger.name):
            with pytest.raises(rollback.RemediationError) as raised:
                rollback.capture_and_remediate(_make_capture_event(), None)

        monkeypatch.undo()
        version_id = _latest_snapshot_version_id()
        assert version_id
        assert f"SnapshotVersionId {version_id}" in str(raised.value)
        logged = [
            record for record in caplog.records if record.levelno == logging.ERROR
        ]
        assert any(
            getattr(record, "snapshotVersionId", None) == version_id
            for record in logged
        )

    def test_read_back_retries_for_at_least_fifteen_seconds(self) -> None:
        # Bucket policies are eventually consistent; a short window fails remediations that did apply.
        retry_window = (rollback._VERIFY_ATTEMPTS - 1) * rollback._VERIFY_DELAY_SECONDS
        assert retry_window >= 15

    @mock_aws
    def test_successful_snapshot_and_remediation(self) -> None:
        _create_snapshot_bucket()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT])

        result = rollback.capture_and_remediate(_make_capture_event(), None)

        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        assert ASR_SID in result["rollbackDescription"]
        policy = _require_policy()
        asr = _asr_statement(policy)
        assert asr is not None
        assert asr["Effect"] == "Deny"
        assert asr["Principal"]["AWS"] == [CROSS_ACCOUNT_PRINCIPAL]
        assert len(policy["Statement"]) == 2
        snap = json.loads(
            boto3.client("s3", config=BOTO_CONFIG)
            .get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"]
            .read()
        )
        assert snap["resourceId"] == BUCKET
        assert snap["postRemediationState"]["AsrStatement"]["Sid"] == ASR_SID
        assert (
            json.loads(snap["preRemediationState"]["BucketPolicy"])["Statement"][0][
                "Sid"
            ]
            == "AllowOtherAccount"
        )

    @mock_aws
    def test_no_op_when_asr_statement_present(self) -> None:
        _create_snapshot_bucket()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "false"
        assert "already present" in result["rollbackDescription"]
        objs = boto3.client("s3", config=BOTO_CONFIG).list_objects_v2(
            Bucket=SNAPSHOT_BUCKET, Prefix=f"snapshots/{EXECUTION_ID}/"
        )
        assert objs.get("KeyCount", 0) == 0

    @mock_aws
    def test_no_op_when_asr_statement_is_in_s3_read_back_form(self) -> None:
        _create_snapshot_bucket()
        written = _built_asr_statement()
        principal_arns = written["Principal"]["AWS"]
        assert len(principal_arns) == 1
        read_back_form = {**written, "Principal": {"AWS": principal_arns[0]}}
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, read_back_form])

        result = rollback.capture_and_remediate(_make_capture_event(), None)

        assert result["snapshotStored"] == "false"
        assert "already present" in result["rollbackDescription"]

    @pytest.mark.parametrize("tamper", NEUTERING_TAMPERS)
    @mock_aws
    def test_rerun_rebuilds_asr_statement_that_was_neutered(
        self, tamper: dict[str, Any]
    ) -> None:
        # Someone with PutBucketPolicy kept the ASR Sid, principals and actions but changed the statement so
        # it no longer denies anything. Matching principals and actions alone must not count as covered.
        _create_snapshot_bucket()
        neutered = {**_built_asr_statement(), **tamper}
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, neutered])

        result = rollback.capture_and_remediate(_make_capture_event(), None)

        assert result["snapshotStored"] == "true"
        live = _asr_statement(_require_policy())
        assert live is not None
        assert rollback._normalize(live) == rollback._normalize(_built_asr_statement())

    @mock_aws
    def test_rerun_denies_cross_account_principal_granted_after_first_run(
        self,
    ) -> None:
        _create_snapshot_bucket()
        _create_bucket(
            [
                ALLOW_CROSS_ACCOUNT_STATEMENT,
                _built_asr_statement(),
                NEW_CROSS_ACCOUNT_STATEMENT,
            ]
        )
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        assert result["snapshotVersionId"] != ""
        assert "Restore the earlier" in result["rollbackDescription"]
        policy = _require_policy()
        asr_statements = [s for s in policy["Statement"] if s.get("Sid") == ASR_SID]
        assert len(asr_statements) == 1
        assert asr_statements[0]["Principal"]["AWS"] == [
            CROSS_ACCOUNT_PRINCIPAL,
            NEW_CROSS_ACCOUNT_PRINCIPAL,
        ]
        assert [s["Sid"] for s in policy["Statement"]] == [
            "AllowOtherAccount",
            ASR_SID,
            "AllowNewAccount",
        ]
        snap = json.loads(
            boto3.client("s3", config=BOTO_CONFIG)
            .get_object(
                Bucket=SNAPSHOT_BUCKET,
                Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            )["Body"]
            .read()
        )
        assert snap["preRemediationState"]["PreviousAsrStatement"] == (
            _built_asr_statement()
        )

    @mock_aws
    def test_rerun_verification_fails_when_old_statement_stays(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _create_snapshot_bucket()
        statements = [
            ALLOW_CROSS_ACCOUNT_STATEMENT,
            _built_asr_statement(),
            NEW_CROSS_ACCOUNT_STATEMENT,
        ]
        _create_bucket(statements)
        _freeze_policy_reads(
            monkeypatch, {"Version": "2012-10-17", "Statement": statements}
        )
        monkeypatch.setattr(rollback, "_VERIFY_DELAY_SECONDS", 0)
        with pytest.raises(rollback.RemediationError, match="Verification failed"):
            rollback.capture_and_remediate(_make_capture_event(), None)

    @mock_aws
    def test_rerun_adds_newly_denylisted_action(self) -> None:
        _create_snapshot_bucket()
        _create_bucket(
            [
                ALLOW_CROSS_ACCOUNT_STATEMENT,
                _built_asr_statement(actions=["s3:PutBucketAcl"]),
            ]
        )
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        asr = _asr_statement(_require_policy())
        assert asr is not None
        assert asr["Action"] == ["s3:PutBucketAcl", "s3:PutBucketPolicy"]

    @mock_aws
    def test_rerun_rebuilds_a_statement_whose_principal_is_no_longer_an_aws_map(
        self,
    ) -> None:
        _create_snapshot_bucket()
        _create_bucket(
            [
                ALLOW_CROSS_ACCOUNT_STATEMENT,
                {**_built_asr_statement(), "Principal": "*"},
            ]
        )
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        asr = _asr_statement(_require_policy())
        assert asr is not None
        assert asr["Principal"] == {"AWS": [CROSS_ACCOUNT_PRINCIPAL]}

    @mock_aws
    def test_rerun_drops_a_covered_principal_that_names_no_account(self) -> None:
        # S3 shows a deleted IAM principal as its unique ID; the rebuilt deny must not carry that ID forward.
        deleted_role_id = "AROAEXAMPLEDELETEDROLE"
        _create_snapshot_bucket()
        _create_bucket(
            [
                ALLOW_CROSS_ACCOUNT_STATEMENT,
                _built_asr_statement(
                    principals=[CROSS_ACCOUNT_PRINCIPAL, deleted_role_id]
                ),
                NEW_CROSS_ACCOUNT_STATEMENT,
            ]
        )
        rollback.capture_and_remediate(_make_capture_event(), None)
        asr = _asr_statement(_require_policy())
        assert asr is not None
        assert asr["Principal"] == {
            "AWS": [CROSS_ACCOUNT_PRINCIPAL, NEW_CROSS_ACCOUNT_PRINCIPAL]
        }

    @pytest.mark.parametrize(
        "existing",
        [
            pytest.param(
                {"Effect": "Allow", "Action": "s3:*"}, id="edited-to-allow-all"
            ),
            pytest.param(
                {
                    "Action": "s3:*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                id="conditional-deny-all",
            ),
        ],
    )
    @mock_aws
    def test_rerun_takes_actions_only_from_an_unconditional_bucket_deny(
        self, existing: dict[str, Any]
    ) -> None:
        _create_snapshot_bucket()
        _create_bucket(
            [ALLOW_CROSS_ACCOUNT_STATEMENT, {**_built_asr_statement(), **existing}]
        )
        rollback.capture_and_remediate(_make_capture_event(), None)
        asr = _asr_statement(_require_policy())
        assert asr is not None
        assert asr["Effect"] == "Deny" and "Condition" not in asr
        assert sorted(rollback._as_str_list(asr["Action"])) == sorted(
            DENYLIST.split(",")
        )

    @mock_aws
    def test_rerun_keeps_actions_removed_from_the_denylist(self) -> None:
        _create_snapshot_bucket()
        _create_bucket(
            [
                ALLOW_CROSS_ACCOUNT_STATEMENT,
                _built_asr_statement(),
                NEW_CROSS_ACCOUNT_STATEMENT,
            ]
        )
        event = {**_make_capture_event(), "DenyList": "s3:PutBucketAcl"}
        rollback.capture_and_remediate(event, None)
        asr = _asr_statement(_require_policy())
        assert asr is not None
        assert asr["Action"] == ["s3:PutBucketAcl", "s3:PutBucketPolicy"]

    @mock_aws
    def test_fail_open_when_config_bucket_missing(self) -> None:
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT])
        result = rollback.capture_and_remediate(
            _make_capture_event(config_bucket="nonexistent-bucket"), None
        )
        assert result["snapshotStored"] == "false"
        assert "Rollback unavailable" in result["rollbackDescription"]
        assert _asr_statement(_get_policy()) is not None

    @mock_aws
    def test_no_bucket_policy_raises(self) -> None:
        _create_snapshot_bucket()
        _create_bucket(None)
        with pytest.raises(rollback.RemediationError, match="no bucket policy"):
            rollback.capture_and_remediate(_make_capture_event(), None)

    @mock_aws
    def test_no_cross_account_principals_raises(self) -> None:
        _create_snapshot_bucket()
        same_account_statement = {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET}/*",
        }
        _create_bucket([same_account_statement])
        with pytest.raises(
            rollback.RemediationError, match="no cross-account principals"
        ):
            rollback.capture_and_remediate(_make_capture_event(), None)

    @mock_aws
    def test_single_object_statement_policy_is_preserved(self) -> None:
        # IAM allows Statement to be a single object (not a list); capture must keep it and add the ASR deny.
        _create_snapshot_bucket()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        s3.create_bucket(Bucket=BUCKET)
        s3.put_bucket_policy(
            Bucket=BUCKET,
            Policy=json.dumps(
                {"Version": "2012-10-17", "Statement": ALLOW_CROSS_ACCOUNT_STATEMENT}
            ),
        )
        result = rollback.capture_and_remediate(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        sids = [s.get("Sid") for s in _require_policy()["Statement"]]
        assert "AllowOtherAccount" in sids  # original single statement preserved
        assert ASR_SID in sids

    @mock_aws
    def test_bucket_not_found_raises(self) -> None:
        _create_snapshot_bucket()
        with pytest.raises(ResourceNotFoundError, match="not found"):
            rollback.capture_and_remediate(_make_capture_event(), None)

    @mock_aws
    def test_missing_bucket_name_raises(self) -> None:
        with pytest.raises(ValueError, match="BucketName"):
            rollback.capture_and_remediate(
                {**_make_capture_event(), "BucketName": ""}, None
            )

    @mock_aws
    def test_invalid_account_id_raises(self) -> None:
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT])
        with pytest.raises(ValueError, match="12-digit"):
            rollback.capture_and_remediate(
                {**_make_capture_event(), "AccountId": "123"}, None
            )


# ── execute_rollback ─────────────────────────────────────────────────────────


class TestExecuteRollback:
    @mock_aws
    def test_verification_failure_when_statement_still_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The removal is issued but the read-back still shows the ASR statement, so rollback must fail closed
        # rather than report a rollback that did not take effect.
        _create_snapshot_bucket()
        asr = _built_asr_statement()
        pre_policy = json.dumps(
            {"Version": "2012-10-17", "Statement": [ALLOW_CROSS_ACCOUNT_STATEMENT]}
        )
        version_id = _put_snapshot(pre_policy=pre_policy, post_asr_statement=asr)
        remediated_policy = {
            "Version": "2012-10-17",
            "Statement": [ALLOW_CROSS_ACCOUNT_STATEMENT, asr],
        }
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, asr])
        _freeze_policy_reads(monkeypatch, remediated_policy)
        monkeypatch.setattr(
            rollback.time, "sleep", lambda _seconds: None
        )  # don't wait out the real backoff
        with pytest.raises(
            rollback.RollbackError, match="Rollback verification failed"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_successful_remove_preserves_other_statements(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "Successfully removed" in result["Message"]
        policy = _require_policy()
        assert _asr_statement(policy) is None
        assert [s["Sid"] for s in policy["Statement"]] == ["AllowOtherAccount"]

    @mock_aws
    def test_rollback_of_rerun_does_not_restore_a_granting_statement(self) -> None:
        # The ASR statement was changed to an Allow; restoring it would grant access, so rollback removes it.
        _create_snapshot_bucket()
        neutered = {**_built_asr_statement(), "Effect": "Allow"}
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, neutered])
        capture = rollback.capture_and_remediate(_make_capture_event(), None)
        assert capture["snapshotStored"] == "true"
        assert capture["rollbackDescription"].startswith("Remove the ASR")

        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=capture["snapshotVersionId"]),
            None,
        )

        assert result["Status"] == "SUCCESS"
        assert _asr_statement(_require_policy()) is None
        assert [s["Sid"] for s in _require_policy()["Statement"]] == [
            "AllowOtherAccount"
        ]

    @pytest.mark.parametrize("tamper", NARROWED_DENY_TAMPERS)
    @mock_aws
    def test_rollback_of_rerun_restores_an_edited_deny(
        self, tamper: dict[str, Any]
    ) -> None:
        _create_snapshot_bucket()
        edited = {**_built_asr_statement(), **tamper}
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, edited])
        capture = rollback.capture_and_remediate(_make_capture_event(), None)
        assert capture["rollbackDescription"].startswith("Restore the earlier")

        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=capture["snapshotVersionId"]),
            None,
        )

        assert result["Status"] == "SUCCESS"
        assert rollback._normalize(
            _asr_statement(_require_policy())
        ) == rollback._normalize(edited)

    @mock_aws
    def test_rollback_of_rerun_restores_earlier_asr_statement(self) -> None:
        _create_snapshot_bucket()
        _create_bucket(
            [
                ALLOW_CROSS_ACCOUNT_STATEMENT,
                _built_asr_statement(),
                NEW_CROSS_ACCOUNT_STATEMENT,
            ]
        )
        capture = rollback.capture_and_remediate(_make_capture_event(), None)
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=capture["snapshotVersionId"]),
            None,
        )
        assert result["Status"] == "SUCCESS"
        assert "restored the earlier" in result["Message"]
        policy = _require_policy()
        assert rollback._normalize(_asr_statement(policy)) == rollback._normalize(
            _built_asr_statement()
        )
        assert [s["Sid"] for s in policy["Statement"]] == [
            "AllowOtherAccount",
            ASR_SID,
            "AllowNewAccount",
        ]
        # A second rollback finds the earlier statement already back and does nothing.
        again = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=capture["snapshotVersionId"]),
            None,
        )
        assert "already in its pre-remediation state" in again["Message"]

    @mock_aws
    def test_rollback_of_first_run_aborts_while_a_widened_statement_is_live(
        self,
    ) -> None:
        _create_snapshot_bucket()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT])
        first = rollback.capture_and_remediate(
            _make_capture_event(execution_id="exec-first"), None
        )
        policy = _require_policy()
        policy["Statement"].append(NEW_CROSS_ACCOUNT_STATEMENT)
        boto3.client("s3", config=BOTO_CONFIG).put_bucket_policy(
            Bucket=BUCKET, Policy=json.dumps(policy)
        )
        second = rollback.capture_and_remediate(
            _make_capture_event(execution_id="exec-second"), None
        )
        widened = _asr_statement(_require_policy())

        with pytest.raises(RollbackError, match="modified"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="exec-first",
                    snapshot_version_id=first["snapshotVersionId"],
                ),
                None,
            )
        assert _asr_statement(_require_policy()) == widened

        # Rolled back newest first, both runs unwind.
        rollback.execute_rollback(
            _make_rollback_event(
                execution_id="exec-second",
                snapshot_version_id=second["snapshotVersionId"],
            ),
            None,
        )
        rollback.execute_rollback(
            _make_rollback_event(
                execution_id="exec-first",
                snapshot_version_id=first["snapshotVersionId"],
            ),
            None,
        )
        assert [s["Sid"] for s in _require_policy()["Statement"]] == [
            "AllowOtherAccount",
            "AllowNewAccount",
        ]

    @mock_aws
    def test_malformed_previous_asr_statement_in_snapshot_raises(self) -> None:
        _create_snapshot_bucket()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        snapshot = {
            "schemaVersion": 1,
            "resourceId": BUCKET,
            "controlId": CONTROL_ID,
            "capturedAt": "2025-01-01T00:00:00+00:00",
            "preRemediationState": {
                "BucketPolicy": "{}",
                "PreviousAsrStatement": "not-an-object",
            },
            "postRemediationState": {"AsrStatement": _built_asr_statement()},
        }
        version_id = boto3.client("s3", config=BOTO_CONFIG).put_object(
            Bucket=SNAPSHOT_BUCKET,
            Key=f"snapshots/{EXECUTION_ID}/{CONTROL_ID}.json",
            Body=json.dumps(snapshot),
            ContentType="application/json",
        )["VersionId"]
        with pytest.raises(SnapshotValidationError, match="PreviousAsrStatement"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _asr_statement(_require_policy()) is not None

    @mock_aws
    def test_rollback_of_rerun_raises_when_earlier_statement_does_not_stick(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(rollback, "_VERIFY_DELAY_SECONDS", 0)
        _create_snapshot_bucket()
        _create_bucket(
            [
                ALLOW_CROSS_ACCOUNT_STATEMENT,
                _built_asr_statement(),
                NEW_CROSS_ACCOUNT_STATEMENT,
            ]
        )
        capture = rollback.capture_and_remediate(_make_capture_event(), None)
        _freeze_policy_reads(monkeypatch, _require_policy())
        with pytest.raises(RollbackError, match="earlier ASR statement is not back"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=capture["snapshotVersionId"]),
                None,
            )

    @mock_aws
    def test_delete_policy_when_only_asr_statement(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot()
        _create_bucket([_built_asr_statement()])
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert _get_policy() is None

    @mock_aws
    def test_noop_when_asr_absent(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT])
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert [s["Sid"] for s in _require_policy()["Statement"]] == [
            "AllowOtherAccount"
        ]

    @mock_aws
    def test_noop_when_policy_deleted_between_remediation_and_rollback(self) -> None:
        # The bucket still exists but its policy was removed after remediation: the ASR statement is gone,
        # so rollback is an idempotent no-op rather than an error or a drift abort.
        _create_snapshot_bucket()
        version_id = _put_snapshot()
        s3 = boto3.client("s3", config=BOTO_CONFIG)
        s3.create_bucket(Bucket=BUCKET)
        result = rollback.execute_rollback(
            _make_rollback_event(snapshot_version_id=version_id), None
        )
        assert result["Status"] == "SUCCESS"
        assert "already in its pre-remediation state" in result["Message"]
        assert _get_policy() is None

    @mock_aws
    def test_drift_when_asr_statement_modified(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot()
        modified = _built_asr_statement(
            principals=[CROSS_ACCOUNT_PRINCIPAL, "arn:aws:iam::888888888888:root"]
        )
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, modified])
        # DriftDetectedError, not SnapshotValidationError: the snapshot is fine, the statement changed.
        with pytest.raises(
            rollback.DriftDetectedError, match="modified after the ASR remediation"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )
        assert _asr_statement(_get_policy()) is not None

    @mock_aws
    def test_missing_snapshot_version_id_raises(self) -> None:
        _create_snapshot_bucket()
        _put_snapshot()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        with pytest.raises(SnapshotValidationError, match="SnapshotVersionId"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=""), None
            )
        assert _asr_statement(_get_policy()) is not None

    @mock_aws
    def test_snapshot_not_found(self) -> None:
        _create_snapshot_bucket()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        with pytest.raises(SnapshotNotFoundError, match="Snapshot not found"):
            rollback.execute_rollback(
                _make_rollback_event(
                    execution_id="missing", snapshot_version_id="no-such-version"
                ),
                None,
            )

    @mock_aws
    def test_resource_id_mismatch_raises(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(resource_id="some-other-bucket")
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        with pytest.raises(
            SnapshotValidationError, match="does not match the target bucket"
        ):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_schema_version_mismatch(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(schema_version=999)
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        with pytest.raises(SnapshotValidationError, match="schema version mismatch"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_malformed_snapshot_missing_asr_statement(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot(omit_asr=True)
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        with pytest.raises(SnapshotValidationError, match="AsrStatement"):
            rollback.execute_rollback(
                _make_rollback_event(snapshot_version_id=version_id), None
            )

    @mock_aws
    def test_missing_account_id_raises(self) -> None:
        _create_snapshot_bucket()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        event = {
            "BucketName": BUCKET,
            "RemediationConfigBucket": SNAPSHOT_BUCKET,
            "ExecutionId": EXECUTION_ID,
            "SnapshotVersionId": "v",
        }
        # Assert the type as well as the message: on the rollback path this must be the RollbackError
        # family, not a bare ValueError (RollbackValidationError is both).
        with pytest.raises(
            rollback.RollbackValidationError,
            match="Missing required parameter: AccountId",
        ):
            rollback.execute_rollback(event, None)


# ── handler dispatch ─────────────────────────────────────────────────────────


def test_rollback_validation_error_is_both_rollback_error_and_value_error() -> None:
    # Every failure the rollback step can raise is a RollbackError, so the SSM caller sees one family;
    # it stays a ValueError because a bad input value is what it is (and the capture path raises that).
    assert issubclass(rollback.RollbackValidationError, RollbackError)
    assert issubclass(rollback.RollbackValidationError, ValueError)


class TestHandler:
    @mock_aws
    def test_dispatches_to_capture_and_remediate(self) -> None:
        _create_snapshot_bucket()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT])
        result = rollback.handler(_make_capture_event(), None)
        assert result["snapshotStored"] == "true"
        assert result["Message"] == ""
        assert result["Status"] == ""
        assert _asr_statement(_get_policy()) is not None

    @mock_aws
    def test_dispatches_to_execute_rollback(self) -> None:
        _create_snapshot_bucket()
        version_id = _put_snapshot()
        _create_bucket([ALLOW_CROSS_ACCOUNT_STATEMENT, _built_asr_statement()])
        event = {
            **_make_rollback_event(snapshot_version_id=version_id),
            "Rollback": "ROLLBACK",
        }
        result = rollback.handler(event, None)
        assert result["Status"] == "SUCCESS"
        assert result["snapshotStored"] == ""
        assert _asr_statement(_get_policy()) is None
