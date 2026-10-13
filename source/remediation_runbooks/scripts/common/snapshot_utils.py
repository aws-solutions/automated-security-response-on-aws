# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# NOTE: Comments are kept minimal to reduce CloudFormation template size.
# This script is embedded inline in rollback-enabled remediation runbooks
# via the %%INCLUDE=common/snapshot_utils.py%% directive.
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Literal, TypedDict, TypeVar

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()

SNAPSHOT_SCHEMA_VERSION = 1


class SnapshotEnvelope(TypedDict):
    """The standard pre-remediation snapshot structure. Only the state dicts are control-specific."""

    schemaVersion: int
    resourceId: str
    controlId: str
    capturedAt: str
    preRemediationState: dict[str, Any]
    postRemediationState: dict[str, Any]


class RollbackError(RuntimeError):
    """Base for rollback failures. Subclasses RuntimeError so SSM Automation marks the step Failed
    (reported as ROLLBACK_FAILED) while still naming the specific failure mode."""


class SnapshotNotFoundError(RollbackError):
    """No pre-remediation snapshot was found in S3 for the execution."""


class SnapshotReadError(RollbackError):
    """Reading the snapshot from S3 failed for a reason other than absence (permissions, network, corruption)."""


class SnapshotValidationError(RollbackError):
    """The snapshot is malformed or has an incompatible schema version."""


def build_snapshot(
    resource_id: str,
    control_id: str,
    pre_state: dict[str, Any],
    post_state: dict[str, Any],
) -> SnapshotEnvelope:
    """Build the standard pre-remediation snapshot envelope. Only the state dicts are control-specific."""
    return {
        "schemaVersion": SNAPSHOT_SCHEMA_VERSION,
        "resourceId": resource_id,
        "controlId": control_id,
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "preRemediationState": pre_state,
        "postRemediationState": post_state,
    }


def get_pre_remediation_state(
    snapshot: dict[str, Any], execution_id: str
) -> dict[str, Any]:
    """Validate the snapshot envelope (schema version + shape) and return its preRemediationState dict.

    The caller extracts and type-checks its own control-specific field(s) from the returned dict.
    """
    version = snapshot.get("schemaVersion", 0)
    if version != SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotValidationError(
            f"Snapshot schema version mismatch: expected {SNAPSHOT_SCHEMA_VERSION}, found {version}."
        )
    pre_state = snapshot.get("preRemediationState")
    if not isinstance(pre_state, dict):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: missing 'preRemediationState' object."
        )
    return pre_state


def get_post_remediation_state(
    snapshot: dict[str, Any], execution_id: str
) -> dict[str, Any]:
    """Validate the snapshot envelope (schema version + shape) and return its postRemediationState dict.

    Mirrors get_pre_remediation_state so the drift-check path shares the same envelope validation.
    The caller extracts and type-checks its own control-specific field(s) from the returned dict.
    """
    version = snapshot.get("schemaVersion", 0)
    if version != SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotValidationError(
            f"Snapshot schema version mismatch: expected {SNAPSHOT_SCHEMA_VERSION}, found {version}."
        )
    post_state = snapshot.get("postRemediationState")
    if not isinstance(post_state, dict):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: missing 'postRemediationState' object."
        )
    return post_state


def write_snapshot(
    bucket: str,
    *,
    execution_id: str,
    control_id: str,
    data: dict[str, Any],
    expected_owner: str = "",
) -> tuple[bool, str | None]:
    """Write pre-remediation snapshot to S3. Returns (success, versionId).

    Fail-open for I/O errors: S3 failures return (False, None) without raising.
    Empty parameters return (False, None) — a runbook started without the rollback
    parameters resolves the document's empty default, leaving nothing to write to.
    """
    if not bucket or not execution_id or not control_id:
        logger.warning("Snapshot write skipped: missing required parameter")
        return False, None
    key = f"snapshots/{execution_id}/{control_id}.json"
    try:
        s3 = boto3.client("s3")
        put_args: dict[str, Any] = {
            "Bucket": bucket,
            "Key": key,
            "Body": json.dumps(data, default=str),
            "ContentType": "application/json",
        }
        if expected_owner:
            put_args["ExpectedBucketOwner"] = expected_owner
        response = s3.put_object(**put_args)
        version_id = response.get("VersionId")
        logger.info(
            "Snapshot written successfully",
            extra={"bucket": bucket, "key": key, "versionId": version_id},
        )
        return True, version_id
    except (ClientError, BotoCoreError):
        logger.exception(
            "Snapshot write failed (fail-open)", extra={"bucket": bucket, "key": key}
        )
        return False, None


def read_snapshot(
    bucket: str,
    *,
    execution_id: str,
    control_id: str,
    version_id: str | None = None,
    expected_owner: str = "",
) -> dict[str, Any] | None:
    """Read snapshot from S3. If version_id is provided, reads that exact version (tamper-proof).

    Returns None only for a genuinely missing snapshot (NoSuchKey/NoSuchBucket/NoSuchVersion);
    other failures (access denied, other S3/network errors, corrupt JSON) raise so the caller
    can surface the real cause.
    """
    if not bucket or not execution_id or not control_id:
        logger.warning("Snapshot read skipped: missing required parameter")
        return None
    key = f"snapshots/{execution_id}/{control_id}.json"
    try:
        s3 = boto3.client("s3")
        params: dict[str, str] = {"Bucket": bucket, "Key": key}
        if version_id:
            params["VersionId"] = version_id
        if expected_owner:
            params["ExpectedBucketOwner"] = expected_owner
        response = s3.get_object(**params)
        parsed = json.loads(response["Body"].read())
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("NoSuchKey", "NoSuchBucket", "NoSuchVersion"):
            logger.error(
                "Snapshot not found",
                extra={
                    "bucket": bucket,
                    "key": key,
                    "versionId": version_id,
                    "errorCode": error_code,
                },
            )
            return None
        logger.exception(
            "Snapshot read failed",
            extra={"bucket": bucket, "key": key, "errorCode": error_code},
        )
        raise
    if not isinstance(parsed, dict):
        raise ValueError(f"Snapshot at s3://{bucket}/{key} is not a JSON object")
    return parsed


class ResourceNotFoundError(RollbackError):
    """The target resource no longer exists (per-control _get_state maps the service's not-found code to this)."""


ROLLBACK_BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


class CaptureResult(TypedDict):
    snapshotStored: Literal["true", "false"]
    snapshotVersionId: str
    rollbackDescription: str


class RollbackResult(TypedDict):
    Message: str
    Status: Literal["SUCCESS"]


class HandlerResult(TypedDict):
    # Every declared SSM output key is always present so the step's selectors resolve on both paths.
    snapshotStored: Literal["", "true", "false"]
    snapshotVersionId: str
    rollbackDescription: str
    Message: str
    Status: Literal["", "SUCCESS"]


class CommonRollbackFields(TypedDict):
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str


def validate_common_rollback_fields(event: dict[str, object]) -> CommonRollbackFields:
    """Validate the fields every rollback event shares; the control adds only its own resource id.

    Missing SnapshotVersionId fails closed (SnapshotValidationError): without it the snapshot can't be
    read as the exact captured, untampered version.
    """
    validated: dict[str, str] = {}
    for name in ("AccountId", "RemediationConfigBucket", "ExecutionId"):
        value = event.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Missing required parameter: {name}")
        validated[name] = value
    # isascii() matters: str.isdigit() is True for non-ASCII digits (e.g. "１２３"), which are not account ids.
    account_id = validated["AccountId"]
    if not account_id.isascii() or not account_id.isdigit() or len(account_id) != 12:
        raise ValueError(
            "Missing or invalid required parameter: AccountId (expected 12-digit AWS account ID)"
        )
    snapshot_version_id = event.get("SnapshotVersionId")
    if not isinstance(snapshot_version_id, str) or not snapshot_version_id:
        raise SnapshotValidationError(
            "Missing required parameter: SnapshotVersionId "
            "(required so the snapshot can be read as the exact captured, untampered version)"
        )
    return CommonRollbackFields(
        AccountId=validated["AccountId"],
        RemediationConfigBucket=validated["RemediationConfigBucket"],
        ExecutionId=validated["ExecutionId"],
        SnapshotVersionId=snapshot_version_id,
    )


def capture_snapshot(
    bucket: str,
    *,
    execution_id: str,
    account_id: str,
    resource_id: str,
    control_id: str,
    pre_state: dict[str, Any],
    post_state: dict[str, Any],
) -> tuple[bool, str]:
    """Write the pre-remediation snapshot to S3 (fail-open); returns (is_stored, versionId).
    Empty bucket/execution_id skips the write. Rollback-availability gate: treat a snapshot as
    rollback-able only when is_stored AND versionId is non-empty (an unversioned bucket returns no
    versionId and rollback fails closed on it)."""
    if not bucket or not execution_id:
        logger.warning(
            "Snapshot skipped: missing bucket or execution ID",
            extra={"bucket": bucket, "executionId": execution_id},
        )
        return False, ""
    data = build_snapshot(resource_id, control_id, pre_state, post_state)
    is_stored, version_id = write_snapshot(
        bucket,
        execution_id=execution_id,
        control_id=control_id,
        data=data,
        expected_owner=account_id,
    )
    return is_stored, version_id or ""


class RollbackAction(Enum):
    NOOP = "noop"
    DRIFT = "drift"
    RESTORE = "restore"


# Binds the three state args to one type so a caller can't mix (e.g. a bool state with a str state).
_State = TypeVar("_State")


def resolve_rollback_action(
    current: _State, original: _State, post: _State
) -> RollbackAction:
    """Decide the rollback outcome from equatable state values (bool, str, ...).

    NOOP is checked before DRIFT so a retried/second rollback (current == original) is idempotent
    success, not a spurious drift error. Relies on original != post (a real remediation changes state;
    a no-op remediation writes no snapshot).
    """
    if current == original:
        return RollbackAction.NOOP
    if current != post:
        return RollbackAction.DRIFT
    return RollbackAction.RESTORE


def dispatch_rollback_handler(
    event: dict[str, object],
    context: object,
    *,
    capture_fn: Callable[[dict[str, object], object], CaptureResult],
    rollback_fn: Callable[[dict[str, object], object], RollbackResult],
) -> HandlerResult:
    """Route on the Rollback parameter and return the unified payload; the control supplies capture_fn/rollback_fn."""
    rollback_flag = event.get("Rollback", "")
    if isinstance(rollback_flag, str) and rollback_flag == "ROLLBACK":
        rollback_result = rollback_fn(event, context)
        return {
            "snapshotStored": "",
            "snapshotVersionId": "",
            "rollbackDescription": "",
            "Message": rollback_result["Message"],
            "Status": rollback_result["Status"],
        }
    capture_result = capture_fn(event, context)
    return {
        "snapshotStored": capture_result["snapshotStored"],
        "snapshotVersionId": capture_result["snapshotVersionId"],
        "rollbackDescription": capture_result["rollbackDescription"],
        "Message": "",
        "Status": "",
    }
