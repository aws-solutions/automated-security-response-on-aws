# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""SSM.7 — EnableSSMDocumentBlockPublicSharing rollback script (shared rollback framework).

capture_and_remediate is fail-open (a snapshot failure never blocks remediation); execute_rollback
is fail-closed (any safety-gate failure aborts, raising RuntimeError so SSM reports ROLLBACK_FAILED).

State is the account-level SSM service setting /ssm/documents/console/public-sharing-permission, a
string that is "Enable" (public sharing allowed) or "Disable" (blocked). The remediation sets it to
"Disable"; rollback restores the captured original value.
"""
from __future__ import annotations

import logging
from typing import Any, Literal, Protocol, TypedDict

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

CONTROL_ID = "SSM.7"

_SETTING_ID = "/ssm/documents/console/public-sharing-permission"
# The account service setting is one of exactly these two values.
SettingValue = Literal["Enable", "Disable"]
_ALLOWED_VALUES: tuple[SettingValue, ...] = ("Enable", "Disable")
_BLOCKED: SettingValue = (
    "Disable"  # public sharing blocked (the remediated/compliant state)
)


class SSMClient(Protocol):
    # Parameter names mirror the boto3 SSM API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def get_service_setting(
        self, *, SettingId: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def update_service_setting(
        self, *, SettingId: str, SettingValue: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names


class CaptureAndRemediateEvent(TypedDict):
    AccountId: str
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str


class ExecuteRollbackEvent(TypedDict):
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str


def _validate_account_id(event: dict[str, object]) -> str:
    account_id = event.get("AccountId")
    if (
        not isinstance(account_id, str)
        or not account_id.isdigit()
        or len(account_id) != 12
    ):
        raise ValueError(
            "Missing or invalid required parameter: AccountId (expected 12-digit AWS account ID)"
        )
    return account_id


def _get_setting(ssm: SSMClient) -> str:
    """Read the account service setting value ("Enable"/"Disable")."""
    response = ssm.get_service_setting(SettingId=_SETTING_ID)
    value = response.get("ServiceSetting", {}).get("SettingValue", "")
    return value if isinstance(value, str) else ""


def _read_pre_state(ssm: SSMClient) -> tuple[str, bool]:
    """Fail-open read of the setting. Returns (value, can_capture_snapshot); on read error returns
    ("", False) so the snapshot is skipped but remediation still proceeds. The first value is
    meaningless unless the second is True."""
    try:
        return _get_setting(ssm), True
    except (ClientError, BotoCoreError):
        logger.exception(
            "Pre-remediation state read failed (fail-open); skipping snapshot"
        )
        return "", False


def _validate_setting_field(
    state: dict[str, Any], field_label: str, execution_id: str
) -> SettingValue:
    """Return the SettingValue from a snapshot state dict, failing closed if it is not one of the known
    values (Enable/Disable) so a malformed or unmodeled snapshot value is never written back.
    """
    value = state.get("SettingValue")
    # Compare against each literal explicitly so mypy narrows Any -> SettingValue (a plain `in` check
    # against a tuple does not narrow the type).
    if value == "Enable":
        return "Enable"
    if value == "Disable":
        return "Disable"
    raise SnapshotValidationError(
        f"Snapshot for execution {execution_id} is malformed: "
        f"'{field_label}.SettingValue' must be one of {_ALLOWED_VALUES}, got {value!r}."
    )


def _validate_pre_setting(snapshot: dict[str, Any], execution_id: str) -> SettingValue:
    """Return the pre-remediation SettingValue (fails closed on a malformed/unmodeled value)."""
    return _validate_setting_field(
        get_pre_remediation_state(snapshot, execution_id),
        "preRemediationState",
        execution_id,
    )


def _validate_post_setting(snapshot: dict[str, Any], execution_id: str) -> SettingValue:
    """Post-state counterpart of _validate_pre_setting; baseline for the drift check."""
    return _validate_setting_field(
        get_post_remediation_state(snapshot, execution_id),
        "postRemediationState",
        execution_id,
    )


def _optional_str(event: dict[str, object], name: str) -> str:
    # Guard fail-open capture fields: a non-string (e.g. None from SSM) becomes "" (skip snapshot), not "None".
    value = event.get(name)
    return value if isinstance(value, str) else ""


def _verify_setting_applied(
    ssm: SSMClient, expected_value: SettingValue, *, error_cls: type[RuntimeError]
) -> None:
    """Re-read the setting and confirm it equals expected_value, else raise error_cls. A silently
    ineffective update must fail rather than report success. Used symmetrically: the remediation path
    expects "Disable", the rollback path expects the restored original value."""
    applied = _get_setting(ssm)
    if applied != expected_value:
        raise error_cls(
            f"SSM block-public-sharing setting is {applied!r} after update, expected {expected_value!r}."
        )


def _validate_capture_event(event: dict[str, object]) -> CaptureAndRemediateEvent:
    account_id = _validate_account_id(event)
    return CaptureAndRemediateEvent(
        AccountId=account_id,
        RemediationConfigBucket=_optional_str(event, "RemediationConfigBucket"),
        AutomationExecutionId=_optional_str(event, "AutomationExecutionId"),
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    # Common fields (incl. AccountId 12-digit shape) are validated by the shared helper.
    common = validate_common_rollback_fields(event)
    return ExecuteRollbackEvent(
        AccountId=common["AccountId"],
        RemediationConfigBucket=common["RemediationConfigBucket"],
        ExecutionId=common["ExecutionId"],
        SnapshotVersionId=common["SnapshotVersionId"],
    )


def _build_rollback_description(
    original_value: str, is_rollback_available: bool
) -> str:
    """Human-readable rollback description for the finding. When no usable snapshot exists, state that
    rollback is unavailable rather than promising a restore that would fail closed."""
    if not is_rollback_available:
        return "Rollback unavailable: pre-remediation state was not captured."
    return f"Restore SSM block-public-sharing setting to {original_value!r}"


def capture_and_remediate(event: dict[str, object], _context: object) -> CaptureResult:
    """Fail-open capture: a snapshot read/write failure never blocks the security remediation."""
    validated = _validate_capture_event(event)
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]

    ssm: SSMClient = boto3.client("ssm", config=ROLLBACK_BOTO_CONFIG)

    original_value, can_capture_snapshot = _read_pre_state(ssm)

    # No-op: already blocked (pre == post). Gated on can_capture_snapshot so a fail-open read can't
    # false-trigger it. The setting is already in the desired state, so no update is needed; skip the
    # snapshot too (avoids a misleading no-op rollback) and don't offer rollback.
    if can_capture_snapshot and original_value == _BLOCKED:
        logger.info(
            "Block public sharing already enabled; no remediation needed, snapshot skipped"
        )
        return {
            "snapshotStored": "false",
            "snapshotVersionId": "",
            "rollbackDescription": "No remediation needed: block public sharing was already enabled.",
        }

    # Capture only when we have a usable, non-empty pre-state value. A successful read can still yield
    # "" (SettingValue absent/non-string); execute_rollback's _validate_pre_setting rejects an empty
    # pre-state as malformed, so capturing one would advertise a rollback that always fails closed.
    # Treat empty original_value as non-capturable: skip the snapshot, report rollback unavailable,
    # remediation still runs.
    can_capture_pre_state = can_capture_snapshot and bool(original_value)

    is_snapshot_stored, snapshot_version_id = (
        capture_snapshot(
            bucket,
            execution_id=execution_id,
            account_id=account_id,
            resource_id=account_id,
            control_id=CONTROL_ID,
            pre_state={"SettingValue": original_value},
            # Intended post-state, written pre-remediation. Guarantees pre != post (so rollback can
            # distinguish drift); a failed remediation leaves an inert orphan snapshot that's never used.
            post_state={"SettingValue": _BLOCKED},
        )
        if can_capture_pre_state
        else (False, "")
    )

    ssm.update_service_setting(SettingId=_SETTING_ID, SettingValue=_BLOCKED)
    logger.info("Block public sharing enabled")
    _verify_setting_applied(ssm, _BLOCKED, error_cls=RuntimeError)

    is_rollback_available = is_snapshot_stored and bool(snapshot_version_id)
    return {
        "snapshotStored": "true" if is_rollback_available else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": _build_rollback_description(
            original_value, is_rollback_available
        ),
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    """Fail-closed rollback: reads the snapshot by its recorded version id (tamper-proof) and aborts
    on drift, so a state the operator set after remediation is never overwritten."""
    validated = _validate_rollback_event(event)
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
            f"Snapshot not found for execution {execution_id}. "
            f"The snapshot may have expired or was never captured."
        )

    original_value = _validate_pre_setting(snapshot, execution_id)
    post_value = _validate_post_setting(snapshot, execution_id)

    ssm: SSMClient = boto3.client("ssm", config=ROLLBACK_BOTO_CONFIG)
    try:
        current_value = _get_setting(ssm)
    except (ClientError, BotoCoreError) as error:
        raise RollbackError(
            f"Failed to read current SSM setting state: {error}"
        ) from error

    action = resolve_rollback_action(current_value, original_value, post_value)
    if action is RollbackAction.NOOP:
        return {
            "Message": "SSM block-public-sharing setting is already in its pre-remediation state. "
            "No rollback action needed.",
            "Status": "SUCCESS",
        }
    if action is RollbackAction.DRIFT:
        raise SnapshotValidationError(
            f"Rollback aborted: current SSM setting ({current_value!r}) does not match the "
            f"post-remediation state ASR applied ({post_value!r}). The setting was modified after "
            f"the ASR remediation."
        )

    try:
        ssm.update_service_setting(SettingId=_SETTING_ID, SettingValue=original_value)
    except (ClientError, BotoCoreError) as error:
        raise RollbackError(
            f"Failed to restore SSM block-public-sharing setting: {error}"
        ) from error
    _verify_setting_applied(ssm, original_value, error_cls=RollbackError)
    logger.info("SSM block-public-sharing setting restored (rollback)")
    return {
        "Message": f"Successfully restored SSM block-public-sharing setting to {original_value!r}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    return dispatch_rollback_handler(
        event, context, capture_fn=capture_and_remediate, rollback_fn=execute_rollback
    )
