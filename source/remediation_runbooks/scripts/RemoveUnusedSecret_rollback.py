# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""SecretsManager.3 — RemoveUnusedSecret rollback script (shared rollback framework).

The remediation deletes a secret that has been unused for longer than UnusedForDays, with a 30-day
recovery window (DeleteSecret schedules the deletion rather than destroying the secret). Rollback calls
RestoreSecret, which cancels that scheduled deletion.

capture_and_remediate is fail-open (a snapshot failure never blocks the security remediation);
execute_rollback is fail-closed (any safety-gate failure aborts, raising RollbackError so SSM reports
ROLLBACK_FAILED). State is whether the secret is scheduled for deletion, so it is binary: False before
the remediation, True after. As with the other boolean-state controls (DynamoDB.6, KMS.4, RDS.7, RDS.8,
RDS.13, RDS.16, ElastiCache.2), that means the DRIFT branch cannot be reached — the live value can only
equal the pre or the post state. The check is kept for a uniform structure. The practical consequence is
that a secret an operator restored and then deliberately re-deleted is indistinguishable from ASR's own
deletion and would be restored again; that is acceptable here because RestoreSecret is non-destructive
(it only cancels a pending deletion and overwrites no secret data), and the operator can delete it again.

Once the 30-day recovery window expires the secret is destroyed and rollback is impossible; that surfaces
as SecretNotFoundError rather than a silent success.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Protocol, TypedDict

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Local import for tests/IDE; the build (runbook_factory.ts) strips this block and inlines
# snapshot_utils.py via the %%INCLUDE directive below — do not remove.
# fmt: off
from common.snapshot_utils import (  # noqa: E402
    ROLLBACK_BOTO_CONFIG,
    CaptureResult,
    HandlerResult,
    ResourceNotFoundError,
    RollbackAction,
    RollbackError,
    RollbackResult,
    SnapshotNotFoundError,
    SnapshotReadError,
    SnapshotValidationError,
    capture_snapshot,
    dispatch_rollback_handler,
    get_post_remediation_state,
    get_pre_remediation_state,
    read_snapshot,
    resolve_rollback_action,
    validate_common_rollback_fields,
)

# fmt: on
# %%INCLUDE=common/snapshot_utils.py%%

CONTROL_ID = "SecretsManager.3"
# The remediation always deletes with a 30-day recovery window, which is what makes rollback possible.
_RECOVERY_WINDOW_IN_DAYS = 30
# Mirrors the SecretARN allowedPattern on the member runbook; defense-in-depth for a direct caller.
_SECRET_ARN_PATTERN = re.compile(
    r"arn:(?:aws|aws-cn|aws-us-gov):secretsmanager:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:secret:[A-Za-z0-9/_+=.@-]+"
)
# UnusedForDays is constrained to ^\d{0,3}$ by the runbook parameter.
_MAX_UNUSED_FOR_DAYS = 999


class SecretsManagerClient(Protocol):
    # Parameter names mirror the boto3 Secrets Manager API (PascalCase kwargs), so S117 does not apply.
    def describe_secret(
        self, *, SecretId: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def delete_secret(
        self, *, SecretId: str, RecoveryWindowInDays: int
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names

    def restore_secret(
        self, *, SecretId: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name


class CaptureAndRemediateEvent(TypedDict):
    SecretARN: str
    AccountId: str
    UnusedForDays: int
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str


class ExecuteRollbackEvent(TypedDict):
    SecretARN: str
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str


class SecretNotFoundError(ResourceNotFoundError):
    """The target secret no longer exists (for a rollback this means the recovery window expired)."""


class RemediationError(RuntimeError):
    """The remediation could not be applied (e.g. the secret was accessed recently, or verification failed)."""


def _validate_secret_arn(event: dict[str, object]) -> str:
    value = event.get("SecretARN")
    if not isinstance(value, str) or not _SECRET_ARN_PATTERN.fullmatch(value):
        raise ValueError(
            "Missing or invalid required parameter: SecretARN (expected a Secrets Manager secret ARN)"
        )
    return value


def _validate_account_id(event: dict[str, object]) -> str:
    account_id = event.get("AccountId")
    if (
        not isinstance(account_id, str)
        or not account_id.isascii()
        or not account_id.isdigit()
        or len(account_id) != 12
    ):
        raise ValueError(
            "Missing or invalid required parameter: AccountId (expected 12-digit AWS account ID)"
        )
    return account_id


def _validate_unused_for_days(event: dict[str, object]) -> int:
    # SSM declares UnusedForDays as an Integer, but a direct caller may pass the digits as a string.
    value = event.get("UnusedForDays")
    if isinstance(value, bool):
        raise ValueError(
            "Missing or invalid required parameter: UnusedForDays (expected a whole number of days)"
        )
    if isinstance(value, int):
        days = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        days = int(value)
    else:
        raise ValueError(
            "Missing or invalid required parameter: UnusedForDays (expected a whole number of days)"
        )
    if days < 0 or days > _MAX_UNUSED_FOR_DAYS:
        raise ValueError(
            f"Missing or invalid required parameter: UnusedForDays (expected 0-{_MAX_UNUSED_FOR_DAYS})"
        )
    return days


def _optional_str(event: dict[str, object], name: str) -> str:
    # Guard fail-open capture fields: a non-string (e.g. None from SSM) becomes "" (skip snapshot), not "None".
    value = event.get(name)
    return value if isinstance(value, str) else ""


def _validate_capture_event(event: dict[str, object]) -> CaptureAndRemediateEvent:
    return CaptureAndRemediateEvent(
        SecretARN=_validate_secret_arn(event),
        AccountId=_validate_account_id(event),
        UnusedForDays=_validate_unused_for_days(event),
        RemediationConfigBucket=_optional_str(event, "RemediationConfigBucket"),
        AutomationExecutionId=_optional_str(event, "AutomationExecutionId"),
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    # Common fields (fail-closed SnapshotVersionId, config bucket, execution id) come from the shared helper.
    # AccountId is re-validated with the local validator on purpose: the shared check is isdigit()+length only,
    # which accepts non-ASCII digits, so using it here would make the rollback path weaker than the capture path.
    common = validate_common_rollback_fields(event)
    return ExecuteRollbackEvent(
        SecretARN=_validate_secret_arn(event),
        AccountId=_validate_account_id(event),
        RemediationConfigBucket=common["RemediationConfigBucket"],
        ExecutionId=common["ExecutionId"],
        SnapshotVersionId=common["SnapshotVersionId"],
    )


def _describe_secret(
    secretsmanager: SecretsManagerClient, secret_arn: str
) -> dict[str, Any]:
    """DescribeSecret, mapping a missing secret to SecretNotFoundError. Other errors propagate."""
    try:
        return secretsmanager.describe_secret(SecretId=secret_arn)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            raise SecretNotFoundError(
                f"Secrets Manager secret {secret_arn} not found."
            ) from error
        raise


def _is_scheduled_for_deletion(secret: dict[str, Any]) -> bool:
    """DescribeSecret reports DeletedDate only while a deletion is scheduled; RestoreSecret clears it."""
    return secret.get("DeletedDate") is not None


def _recovery_window_elapsed_error(secret_arn: str) -> SecretNotFoundError:
    """The secret is gone, so rollback is impossible.

    This can surface from DescribeSecret or from RestoreSecret: after a force-delete, DescribeSecret can
    still report the secret (with DeletedDate set) for a short window while RestoreSecret already fails,
    so both call sites map to the same explicit message.
    """
    return SecretNotFoundError(
        f"Rollback aborted for secret {secret_arn}: the secret no longer exists, so its "
        f"{_RECOVERY_WINDOW_IN_DAYS}-day recovery window has elapsed and it cannot be restored."
    )


def _require_scheduled_flag(
    state: Mapping[str, object],
    execution_id: str,
    label: Literal["preRemediationState", "postRemediationState"],
) -> bool:
    """Read the deletion flag out of an as-parsed snapshot state.

    The parameter is deliberately NOT a TypedDict: `state` comes straight from the snapshot JSON and is
    therefore unvalidated, and validating it is this function's whole purpose. Declaring the validated
    shape on the way in would assert the very thing being checked.
    """
    value = state.get("IsScheduledForDeletion")
    if not isinstance(value, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: missing '{label}.IsScheduledForDeletion' boolean."
        )
    return value


def _is_unused_beyond_threshold(secret: dict[str, Any], unused_for_days: int) -> bool:
    """Whether the secret's last access is older than the threshold.

    A secret with no LastAccessedDate is NOT deleted, preserving the pre-rollback remediation's behaviour.
    """
    last_accessed = secret.get("LastAccessedDate")
    if not isinstance(last_accessed, datetime):
        return False
    # Secrets Manager tracks LastAccessedDate at day granularity, so compare against midnight UTC today.
    today = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return (today - last_accessed).days > unused_for_days


def capture_and_remediate(event: dict[str, object], _context: object) -> CaptureResult:
    """Fail-open capture: a snapshot read/write failure never blocks the security remediation."""
    validated = _validate_capture_event(event)
    secret_arn = validated["SecretARN"]
    account_id = validated["AccountId"]
    unused_for_days = validated["UnusedForDays"]
    config_bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]

    secretsmanager: SecretsManagerClient = boto3.client(
        "secretsmanager", config=ROLLBACK_BOTO_CONFIG
    )
    secret = _describe_secret(secretsmanager, secret_arn)

    # No-op: the secret is already scheduled for deletion (e.g. a re-run). Skip the snapshot — capturing
    # "already scheduled" as the pre-remediation state would make a later rollback restore a deletion ASR
    # did not cause — and don't re-delete.
    if _is_scheduled_for_deletion(secret):
        logger.info(
            "Secret already scheduled for deletion; no remediation needed, snapshot skipped"
        )
        return {
            "snapshotStored": "false",
            "snapshotVersionId": "",
            "rollbackDescription": "No remediation needed: the secret was already scheduled for deletion.",
        }

    if not _is_unused_beyond_threshold(secret, unused_for_days):
        raise RemediationError(
            f"The secret {secret_arn} cannot be deleted because it has been accessed within the past "
            f"{unused_for_days} days."
        )

    # Snapshot before mutating. Fail-open: a snapshot failure must not block the remediation.
    is_snapshot_stored, snapshot_version_id = capture_snapshot(
        config_bucket,
        execution_id=execution_id,
        account_id=account_id,
        resource_id=secret_arn,
        control_id=CONTROL_ID,
        pre_state={"IsScheduledForDeletion": False},
        post_state={"IsScheduledForDeletion": True},
    )

    secretsmanager.delete_secret(
        SecretId=secret_arn, RecoveryWindowInDays=_RECOVERY_WINDOW_IN_DAYS
    )
    # Confirm the deletion was scheduled before reporting success.
    if not _is_scheduled_for_deletion(_describe_secret(secretsmanager, secret_arn)):
        raise RemediationError(
            f"Verification failed: the secret {secret_arn} is not scheduled for deletion after the update."
        )
    logger.info(
        "Unused secret scheduled for deletion",
        extra={"recoveryWindowInDays": _RECOVERY_WINDOW_IN_DAYS},
    )

    is_rollback_available = is_snapshot_stored and bool(snapshot_version_id)
    rollback_description = (
        f"Cancel the scheduled deletion of secret {secret_arn} (restore it)"
        if is_rollback_available
        else "Rollback unavailable: pre-remediation state was not captured."
    )
    return {
        "snapshotStored": "true" if is_rollback_available else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": rollback_description,
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    """Fail-closed rollback: reads the snapshot by its recorded version id (tamper-proof), aborts on drift,
    and cancels the scheduled deletion with RestoreSecret."""
    validated = _validate_rollback_event(event)
    secret_arn = validated["SecretARN"]
    account_id = validated["AccountId"]
    config_bucket = validated["RemediationConfigBucket"]
    execution_id = validated["ExecutionId"]
    snapshot_version_id = validated["SnapshotVersionId"]

    try:
        snapshot = read_snapshot(
            config_bucket,
            execution_id=execution_id,
            control_id=CONTROL_ID,
            version_id=snapshot_version_id,
            expected_owner=account_id,
        )
    except ValueError as error:
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: {error}"
        ) from error
    except (ClientError, BotoCoreError) as error:
        raise SnapshotReadError(
            f"Failed to read snapshot for execution {execution_id}: {error}"
        ) from error
    if snapshot is None:
        raise SnapshotNotFoundError(
            f"Snapshot not found for execution {execution_id}. The snapshot may have expired or was never captured."
        )

    # Guard against an execution id resolving to another resource's snapshot.
    snapshot_resource_id = snapshot.get("resourceId")
    if snapshot_resource_id != secret_arn:
        raise SnapshotValidationError(
            f"Rollback aborted for secret {secret_arn}: snapshot resourceId ({snapshot_resource_id!r}) "
            f"does not match the target secret ({secret_arn!r})."
        )

    was_originally_scheduled = _require_scheduled_flag(
        get_pre_remediation_state(snapshot, execution_id),
        execution_id,
        "preRemediationState",
    )
    was_scheduled_post_remediation = _require_scheduled_flag(
        get_post_remediation_state(snapshot, execution_id),
        execution_id,
        "postRemediationState",
    )

    secretsmanager: SecretsManagerClient = boto3.client(
        "secretsmanager", config=ROLLBACK_BOTO_CONFIG
    )
    # A secret whose recovery window has elapsed is destroyed and cannot be restored: fail closed rather
    # than report a misleading success.
    try:
        secret = _describe_secret(secretsmanager, secret_arn)
    except SecretNotFoundError as error:
        raise _recovery_window_elapsed_error(secret_arn) from error
    is_currently_scheduled = _is_scheduled_for_deletion(secret)

    action = resolve_rollback_action(
        is_currently_scheduled, was_originally_scheduled, was_scheduled_post_remediation
    )
    if action is RollbackAction.NOOP:
        return {
            "Message": f"Secret {secret_arn} is not scheduled for deletion; already in its pre-remediation state.",
            "Status": "SUCCESS",
        }
    if (
        action is RollbackAction.DRIFT
    ):  # pragma: no cover - unreachable for a binary state (see module docstring)
        raise SnapshotValidationError(
            f"Rollback aborted for secret {secret_arn}: its deletion state changed after the ASR remediation."
        )

    try:
        secretsmanager.restore_secret(SecretId=secret_arn)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            raise _recovery_window_elapsed_error(secret_arn) from error
        raise
    # Confirm the scheduled deletion is cancelled before reporting success.
    if _is_scheduled_for_deletion(_describe_secret(secretsmanager, secret_arn)):
        raise RollbackError(
            f"Rollback verification failed: secret {secret_arn} is still scheduled for deletion."
        )
    logger.info("Scheduled deletion cancelled (rollback)")
    return {
        "Message": f"Successfully cancelled the scheduled deletion of secret {secret_arn}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    return dispatch_rollback_handler(
        event, context, capture_fn=capture_and_remediate, rollback_fn=execute_rollback
    )
