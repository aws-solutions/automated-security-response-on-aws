# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""KMS.4 — EnableKeyRotation rollback script (shared rollback framework).

capture_and_remediate is fail-open (a snapshot failure never blocks remediation); execute_rollback
is fail-closed (any safety-gate failure aborts). Rollback failures raise RuntimeError so SSM
Automation marks the step Failed, which the orchestrator reports as ROLLBACK_FAILED.
"""
from __future__ import annotations

import logging
from typing import Any, Literal, Protocol, TypedDict

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Local import for tests/IDE; the build (runbook_factory.ts) strips this block and inlines
# snapshot_utils.py via the %%INCLUDE directive below — do not remove.
# fmt: off
from common.snapshot_utils import (  # noqa: E402
    SnapshotNotFoundError,
    SnapshotReadError,
    SnapshotValidationError,
    build_snapshot,
    get_post_remediation_state,
    get_pre_remediation_state,
    read_snapshot,
    write_snapshot,
)

# fmt: on
# %%INCLUDE=common/snapshot_utils.py%%

CONTROL_ID = "KMS.4"

# Standard-mode retries so transient KMS throttling does not spuriously fail the step.
BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


class KMSClient(Protocol):
    # Parameter names mirror the boto3 KMS API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def get_key_rotation_status(
        self, *, KeyId: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def enable_key_rotation(
        self, *, KeyId: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def disable_key_rotation(
        self, *, KeyId: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name


class CaptureAndRemediateEvent(TypedDict):
    KeyId: str
    AccountId: str
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str


class ExecuteRollbackEvent(TypedDict):
    KeyId: str
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str


class CaptureResult(TypedDict):
    snapshotStored: Literal["true", "false"]
    snapshotVersionId: str
    rollbackDescription: str


class RollbackResult(TypedDict):
    Message: str
    Status: Literal["SUCCESS"]


class HandlerResult(TypedDict):
    """Unified payload: every declared SSM output key is always present so the collapsed step's
    selectors resolve on both paths."""

    snapshotStored: str
    snapshotVersionId: str
    rollbackDescription: str
    Message: str
    Status: str


def _validate_key_id(event: dict[str, object]) -> str:
    key_id = event.get("KeyId")
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("Missing or invalid required parameter: KeyId")
    return key_id


def _get_rotation_enabled(kms: KMSClient, key_id: str) -> bool:
    return bool(kms.get_key_rotation_status(KeyId=key_id)["KeyRotationEnabled"])


def _read_pre_state(kms: KMSClient, key_id: str) -> tuple[bool, bool]:
    """Read pre-remediation state (fail-open). Returns (rotation_enabled, can_capture_snapshot);
    on read error returns (False, False) so the snapshot is skipped but remediation still proceeds.
    The first value is meaningless unless the second is True."""
    try:
        return _get_rotation_enabled(kms, key_id), True
    except (ClientError, BotoCoreError):
        logger.exception(
            "Pre-remediation state read failed (fail-open); skipping snapshot",
            extra={"keyId": key_id},
        )
        return False, False


def _read_pre_rotation_enabled(snapshot: dict[str, Any], execution_id: str) -> bool:
    """Assert the field is a real bool so a malformed snapshot fails closed (not coerced)."""
    pre_state = get_pre_remediation_state(snapshot, execution_id)
    enabled = pre_state.get("KeyRotationEnabled")
    if not isinstance(enabled, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'preRemediationState.KeyRotationEnabled'."
        )
    return enabled


def _read_post_rotation_enabled(snapshot: dict[str, Any], execution_id: str) -> bool:
    """Post-state counterpart of _read_pre_rotation_enabled; baseline for the drift check."""
    post_state = get_post_remediation_state(snapshot, execution_id)
    enabled = post_state.get("KeyRotationEnabled")
    if not isinstance(enabled, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'postRemediationState.KeyRotationEnabled'."
        )
    return enabled


def _optional_str(event: dict[str, object], name: str) -> str:
    """Return the value only if it is a real string, else "". Guards the fail-open capture fields so a
    non-string (e.g. None from SSM) becomes "" (skip snapshot) rather than str(None) == "None".
    """
    value = event.get(name)
    return value if isinstance(value, str) else ""


def _validate_capture_event(event: dict[str, object]) -> CaptureAndRemediateEvent:
    """Validate the SSM-supplied capture event at the module boundary and return a narrowed object."""
    key_id = _validate_key_id(event)
    account_id = event.get("AccountId")
    if not isinstance(account_id, str) or not account_id:
        raise ValueError("Missing required parameter: AccountId")
    return CaptureAndRemediateEvent(
        KeyId=key_id,
        AccountId=account_id,
        RemediationConfigBucket=_optional_str(event, "RemediationConfigBucket"),
        AutomationExecutionId=_optional_str(event, "AutomationExecutionId"),
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    """Validate the SSM-supplied rollback event at the module boundary and return a narrowed object."""
    key_id = _validate_key_id(event)
    validated: dict[str, str] = {}
    for name in ("AccountId", "RemediationConfigBucket", "ExecutionId"):
        value = event.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Missing required parameter: {name}")
        validated[name] = value
    # SnapshotVersionId must be present: rollback reads the exact captured version for tamper-proofing.
    snapshot_version_id = event.get("SnapshotVersionId")
    if not isinstance(snapshot_version_id, str) or not snapshot_version_id:
        raise SnapshotValidationError(
            f"Rollback aborted for execution {validated['ExecutionId']}: no snapshot version ID recorded, "
            f"so the snapshot cannot be verified as untampered."
        )
    return ExecuteRollbackEvent(
        KeyId=key_id,
        AccountId=validated["AccountId"],
        RemediationConfigBucket=validated["RemediationConfigBucket"],
        ExecutionId=validated["ExecutionId"],
        SnapshotVersionId=snapshot_version_id,
    )


def _capture_snapshot(
    bucket: str,
    *,
    execution_id: str,
    account_id: str,
    key_id: str,
    was_rotation_enabled: bool,
) -> tuple[bool, str]:
    """Write the pre-remediation snapshot to S3 (fail-open); returns (is_stored, versionId).
    Empty bucket/execution_id skips the write."""
    if not bucket or not execution_id:
        logger.warning(
            "Snapshot skipped: missing bucket or execution ID",
            extra={"bucket": bucket, "executionId": execution_id},
        )
        return False, ""
    snapshot_data = build_snapshot(
        key_id,
        CONTROL_ID,
        {"KeyRotationEnabled": was_rotation_enabled},
        # intended post-state (written pre-enable); a failed enable leaves an inert orphan which is never used
        {"KeyRotationEnabled": True},
    )
    is_stored, version_id = write_snapshot(
        bucket,
        execution_id=execution_id,
        control_id=CONTROL_ID,
        data=snapshot_data,
        expected_owner=account_id,
    )
    return is_stored, version_id or ""


def capture_and_remediate(event: dict[str, object], _context: object) -> CaptureResult:
    """Capture handler. Fail-open: a snapshot read/write failure must never block the security
    remediation, so capture is best-effort and enable_key_rotation always runs."""
    validated = _validate_capture_event(event)
    key_id = validated["KeyId"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]

    kms: KMSClient = boto3.client("kms", config=BOTO_CONFIG)

    is_currently_enabled, can_capture_snapshot = _read_pre_state(kms, key_id)

    # No-op remediation: rotation already enabled (pre == post). Gated on can_capture_snapshot so a
    # fail-open read error (is_currently_enabled=False, meaningless) doesn't false-trigger this.
    # Skip the snapshot so a later rollback of this finding isn't a misleading no-op, and don't offer
    # rollback. Still call enable_key_rotation for idempotency in case the pre-state read was stale.
    if can_capture_snapshot and is_currently_enabled:
        kms.enable_key_rotation(KeyId=key_id)
        logger.info(
            "Key rotation already enabled; no remediation needed, snapshot skipped",
            extra={"keyId": key_id},
        )
        return {
            "snapshotStored": "false",
            "snapshotVersionId": "",
            "rollbackDescription": "No remediation needed: key rotation was already enabled.",
        }

    is_snapshot_stored, snapshot_version_id = (
        _capture_snapshot(
            bucket,
            execution_id=execution_id,
            account_id=account_id,
            key_id=key_id,
            was_rotation_enabled=is_currently_enabled,
        )
        if can_capture_snapshot
        else (False, "")
    )

    kms.enable_key_rotation(KeyId=key_id)
    logger.info("Key rotation enabled", extra={"keyId": key_id})

    return {
        "snapshotStored": "true" if is_snapshot_stored else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": f"Disable key rotation for key {key_id}",
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    """Rollback handler. Fail-closed: reads the snapshot by its recorded version id (tamper-proof)
    and aborts on any drift, so a state the operator set after remediation is never overwritten.
    """
    validated = _validate_rollback_event(event)
    key_id = validated["KeyId"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["ExecutionId"]
    snapshot_version_id = validated["SnapshotVersionId"]

    try:
        snapshot = read_snapshot(
            bucket,
            execution_id=execution_id,
            control_id=CONTROL_ID,
            version_id=snapshot_version_id,
            expected_owner=account_id,
        )
    except (ClientError, BotoCoreError, ValueError) as error:
        raise SnapshotReadError(
            f"Failed to read snapshot for execution {execution_id}: {error}"
        ) from error
    if snapshot is None:
        raise SnapshotNotFoundError(
            f"Snapshot not found for execution {execution_id}. "
            f"The snapshot may have expired or was never captured."
        )

    was_originally_enabled = _read_pre_rotation_enabled(snapshot, execution_id)
    was_post_remediation_enabled = _read_post_rotation_enabled(snapshot, execution_id)

    kms: KMSClient = boto3.client("kms", config=BOTO_CONFIG)
    is_currently_enabled = _get_rotation_enabled(kms, key_id)

    # Idempotent no-op / already rolled back: if the key is already in its pre-remediation state,
    # return SUCCESS. This MUST precede the drift gate — on a second rollback current == original
    # (and original != post for a real remediation), which would otherwise trip the drift error.
    if is_currently_enabled == was_originally_enabled:
        return {
            "Message": f"Key {key_id} is already in its pre-remediation state. No rollback action needed.",
            "Status": "SUCCESS",
        }

    if is_currently_enabled != was_post_remediation_enabled:
        raise SnapshotValidationError(
            f"Rollback aborted for key {key_id}: current key rotation ({is_currently_enabled}) "
            f"does not match the post-remediation state ASR applied ({was_post_remediation_enabled}). "
            f"The resource was modified after the ASR remediation."
        )

    # Restore the actual pre-remediation state. Branch on the target rather than assuming direction,
    # so this stays correct regardless of what postRemediationState holds.
    if was_originally_enabled:
        kms.enable_key_rotation(KeyId=key_id)
    else:
        kms.disable_key_rotation(KeyId=key_id)
    logger.info("Key rotation restored (rollback)", extra={"keyId": key_id})
    return {
        "Message": f"Successfully restored key rotation to {was_originally_enabled} for key {key_id}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    """Single inline entry point: dispatch on the Rollback parameter; return the unified payload."""
    if str(event.get("Rollback", "")) == "ROLLBACK":
        rollback_result = execute_rollback(event, context)
        return {
            "snapshotStored": "",
            "snapshotVersionId": "",
            "rollbackDescription": "",
            "Message": rollback_result["Message"],
            "Status": rollback_result["Status"],
        }
    capture_result = capture_and_remediate(event, context)
    return {
        "snapshotStored": capture_result["snapshotStored"],
        "snapshotVersionId": capture_result["snapshotVersionId"],
        "rollbackDescription": capture_result["rollbackDescription"],
        "Message": "",
        "Status": "",
    }
