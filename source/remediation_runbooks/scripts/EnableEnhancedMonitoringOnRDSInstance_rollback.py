# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""RDS.6 — EnableEnhancedMonitoringOnRDSInstance rollback script (shared rollback framework).

capture_and_remediate is fail-open (a snapshot failure never blocks remediation); execute_rollback
is fail-closed (any safety-gate failure aborts, raising RuntimeError so SSM reports ROLLBACK_FAILED).
State is the instance's enhanced monitoring: MonitoringInterval (the compliance signal; 0 = disabled)
and the coupled MonitoringRoleArn (required when the interval is non-zero).
"""
from __future__ import annotations

import logging
import time
from typing import Any, Literal, Protocol, TypedDict, TypeGuard

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

CONTROL_ID = "RDS.6"

_INSTANCE_ARN_MARKER = ":db:"
_VALID_PARTITIONS = ("aws", "aws-cn", "aws-us-gov")
_INVALID_INSTANCE_ARN_MESSAGE = "Missing or invalid required parameter: RDSInstanceARN (expected an RDS DB instance ARN)"
# MonitoringInterval is one of a small fixed set (0 = enhanced monitoring disabled). Modeled as a Literal
# so the validated interval carries its constraint through the type system (ADR-0001: narrow types).
MonitoringInterval = Literal[0, 1, 5, 10, 15, 30, 60]
_VALID_MONITORING_INTERVALS: frozenset[int] = frozenset({0, 1, 5, 10, 15, 30, 60})
# RDS.6 enables enhanced monitoring, so a remediation *target* must be positive; 0 (disabled) is valid
# only as a captured pre-remediation state (read via _require_interval), never as a target.
_VALID_TARGET_INTERVALS: frozenset[int] = frozenset({1, 5, 10, 15, 30, 60})
# The remediation *target* excludes 0 (disabling monitoring is never a valid RDS.6 target), so it carries
# a narrower type than a general MonitoringInterval.
TargetMonitoringInterval = Literal[1, 5, 10, 15, 30, 60]
# Post-modification verification poll: ModifyDBInstance is asynchronous and the instance can briefly still
# report "available" with the old value, so poll until the state matches rather than checking once. The
# sleep budget (10 x 15s = 150s) is kept well under the runbook step's 600s timeoutSeconds so a genuine
# mismatch surfaces as MonitoringVerificationError rather than being cut off by a generic step timeout.
_VERIFY_MAX_ATTEMPTS = 10
_VERIFY_DELAY_SECONDS = 15


class RDSClient(Protocol):
    # Parameter names mirror the boto3 RDS API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def describe_db_instances(
        self, *, DBInstanceIdentifier: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    # MonitoringRoleArn is optional: it is passed only for a non-zero interval (RDS requires it omitted at 0).
    def modify_db_instance(  # NOSONAR boto3 API parameter names
        self,
        *,
        DBInstanceIdentifier: str,
        MonitoringInterval: MonitoringInterval,
        ApplyImmediately: bool,
        MonitoringRoleArn: str = "",
    ) -> dict[str, Any]: ...


class CaptureAndRemediateEvent(TypedDict):
    RDSInstanceARN: str
    AccountId: str
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str
    MonitoringInterval: TargetMonitoringInterval
    MonitoringRoleArn: str
    ApplyImmediately: bool


class ExecuteRollbackEvent(TypedDict):
    RDSInstanceARN: str
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str
    ApplyImmediately: bool


class MonitoringVerificationError(RollbackError):
    """Enhanced monitoring did not reach the expected MonitoringInterval after the modify."""


def _parse_arn(value: object) -> tuple[str, list[str]] | None:
    """Return (arn, segments) for a structurally valid 6-segment ARN with a known partition, else None
    (so a lookalike string can't pass a substring check)."""
    if not isinstance(value, str):
        return None
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[1] not in _VALID_PARTITIONS:
        return None
    return value, parts


def _validate_instance_arn(event: dict[str, object], account_id: str) -> str:
    """Validate the RDS DB instance ARN (arn:partition:rds:region:account:db:instance-id) and confirm its
    account matches account_id (defense-in-depth against operating on a cross-account instance).
    """
    parsed = _parse_arn(event.get("RDSInstanceARN"))
    if parsed is None:
        raise ValueError(_INVALID_INSTANCE_ARN_MESSAGE)
    rds_instance_arn, parts = parsed
    if (
        parts[2] != "rds"
        or not parts[3]
        or not parts[4].isdigit()
        or len(parts[4]) != 12
        or not parts[5].startswith("db:")
        or not parts[5].split("db:", 1)[1]
    ):
        raise ValueError(_INVALID_INSTANCE_ARN_MESSAGE)
    if parts[4] != account_id:
        raise ValueError(
            f"RDSInstanceARN account ({parts[4]}) does not match the executing account ({account_id}); "
            f"refusing to operate on a cross-account instance."
        )
    return rds_instance_arn


def _instance_id_from_arn(rds_instance_arn: str) -> str:
    return rds_instance_arn.split(_INSTANCE_ARN_MARKER, 1)[1]


def _is_monitoring_interval(value: object) -> TypeGuard[MonitoringInterval]:
    # Runtime membership check that also narrows int -> MonitoringInterval for the type checker (no cast).
    # bool is an int subclass in Python, so exclude it explicitly.
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in _VALID_MONITORING_INTERVALS
    )


def _is_target_interval(value: object) -> TypeGuard[TargetMonitoringInterval]:
    # Narrows int -> TargetMonitoringInterval (the non-zero remediation targets) for the type checker.
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in _VALID_TARGET_INTERVALS
    )


def _require_interval(
    value: object, *, execution_id: str, state_label: str
) -> MonitoringInterval:
    if _is_monitoring_interval(value):
        return value
    raise SnapshotValidationError(
        f"Snapshot for execution {execution_id} is malformed: missing valid integer '{state_label}.MonitoringInterval'."
    )


def _validate_monitoring_interval(value: object) -> TargetMonitoringInterval:
    # Validate the remediation *target* interval at the boundary. SSM sends it as an Integer parameter
    # (int or str in the payload). 0 (disabled) is rejected: RDS.6 enables enhanced monitoring, so the
    # target must be positive — mirroring the SSM parameter's allowedValues of [1, 5, 10, 15, 30, 60].
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"Invalid MonitoringInterval: {value!r} (expected an integer)")
    try:
        interval = int(value)
    except ValueError as error:
        raise ValueError(
            f"Invalid MonitoringInterval: {value!r} (expected an integer)"
        ) from error
    if not _is_target_interval(interval):
        raise ValueError(
            f"Invalid MonitoringInterval: {interval} (expected one of {sorted(_VALID_TARGET_INTERVALS)})"
        )
    return interval


def _validate_apply_immediately(value: object) -> bool:
    # Narrow explicitly (ADR-0001) rather than coercing an arbitrary object via str(value). SSM sends this as
    # a Boolean, so accept a real bool or the "true"/"false" strings, and reject anything else clearly.
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise ValueError(
        f"Invalid ApplyImmediately value: {value!r} (expected a bool or 'true'/'false')"
    )


def _optional_str(value: object) -> str:
    # Optional string parameters narrow to "" for any non-string, preserving fail-open behavior
    # (empty -> skip snapshot) rather than coercing None/numbers into bogus strings (e.g. str(None) == "None").
    return value if isinstance(value, str) else ""


def _monitoring_state_key(
    interval: MonitoringInterval, role: str
) -> tuple[MonitoringInterval, str]:
    # State key for resolve_rollback_action. The role is only meaningful when monitoring is enabled: at
    # interval 0 RDS omits the role and retains a stale ARN, so normalize it to "" to avoid a false drift
    # (and to keep a re-run rollback idempotent).
    return interval, ("" if interval == 0 else role)


def _get_monitoring_state(
    rds: RDSClient, db_instance_id: str
) -> tuple[MonitoringInterval, str]:
    """Return the instance's current (MonitoringInterval, MonitoringRoleArn). Interval is 0 when disabled."""
    try:
        instances = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id).get(
            "DBInstances", []
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            raise ResourceNotFoundError(
                f"RDS DB instance {db_instance_id} not found."
            ) from error
        raise
    if not instances:
        raise ResourceNotFoundError(f"RDS DB instance {db_instance_id} not found.")
    interval = instances[0].get("MonitoringInterval", 0)
    role = instances[0].get("MonitoringRoleArn", "")
    if not _is_monitoring_interval(interval):
        raise MonitoringVerificationError(
            f"RDS returned an unexpected MonitoringInterval ({interval!r}) for RDS instance {db_instance_id}; "
            f"cannot safely determine the monitoring state."
        )
    return interval, _optional_str(role)


def _read_pre_state(
    rds: RDSClient, db_instance_id: str
) -> tuple[MonitoringInterval, str, bool]:
    try:
        interval, role = _get_monitoring_state(rds, db_instance_id)
        return interval, role, True
    except (ClientError, BotoCoreError, MonitoringVerificationError):
        logger.exception(
            "Pre-remediation state read failed (fail-open); skipping snapshot",
            extra={"dbInstanceId": db_instance_id},
        )
        return 0, "", False


def _modify_monitoring(
    rds: RDSClient,
    db_instance_id: str,
    *,
    interval: MonitoringInterval,
    role: str,
    apply_immediately: bool,
) -> None:
    # Enabling enhanced monitoring (interval != 0) requires a MonitoringRoleArn; validate early with a clear
    # error rather than letting RDS reject the call with a confusing message. Interval 0 must omit the role.
    if interval != 0 and not role:
        raise ValueError(
            f"MonitoringRoleArn is required to enable enhanced monitoring on {db_instance_id} (interval {interval})."
        )
    # Explicit typed kwargs per branch (rather than a dict[str, Any] + **unpack): keeps each argument's
    # narrow type (ADR-0001) and omits MonitoringRoleArn at interval 0, which the RDS API requires.
    if interval != 0:
        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            MonitoringInterval=interval,
            ApplyImmediately=apply_immediately,
            MonitoringRoleArn=role,
        )
    else:
        rds.modify_db_instance(
            DBInstanceIdentifier=db_instance_id,
            MonitoringInterval=interval,
            ApplyImmediately=apply_immediately,
        )


def _wait_and_verify_state(
    rds: RDSClient,
    db_instance_id: str,
    *,
    expected_interval: MonitoringInterval,
    expected_role: str,
) -> None:
    # ModifyDBInstance is asynchronous: describe_db_instances can briefly still report the OLD value after the
    # call returns, so poll the instance's state until it matches rather than checking once. Polling the target
    # field directly (no db_instance_available waiter, which has its own unbounded timeout) keeps the worst
    # case bounded to _VERIFY_MAX_ATTEMPTS x _VERIFY_DELAY_SECONDS (10 x 15s = 150s) — well under the runbook
    # step's 600s timeoutSeconds, so a genuine mismatch surfaces as MonitoringVerificationError rather than a
    # generic step timeout. Role is compared normalized (irrelevant at interval 0; see _monitoring_state_key).
    expected_key = _monitoring_state_key(expected_interval, expected_role)
    for attempt in range(_VERIFY_MAX_ATTEMPTS):
        actual_interval, actual_role = _get_monitoring_state(rds, db_instance_id)
        if _monitoring_state_key(actual_interval, actual_role) == expected_key:
            return
        if attempt == _VERIFY_MAX_ATTEMPTS - 1:
            raise MonitoringVerificationError(
                f"Enhanced monitoring verification failed for RDS instance {db_instance_id}: "
                f"expected (interval={expected_interval}, role={expected_role!r}), "
                f"found (interval={actual_interval}, role={actual_role!r})."
            )
        time.sleep(_VERIFY_DELAY_SECONDS)


def _validate_capture_event(event: dict[str, object]) -> CaptureAndRemediateEvent:
    account_id = event.get("AccountId")
    if (
        not isinstance(account_id, str)
        or not account_id.isdigit()
        or len(account_id) != 12
    ):
        raise ValueError(
            "Missing or invalid required parameter: AccountId (expected 12-digit AWS account ID)"
        )
    rds_instance_arn = _validate_instance_arn(event, account_id)
    target_interval = _validate_monitoring_interval(event.get("MonitoringInterval", 60))
    # The target always enables enhanced monitoring (interval > 0), which RDS requires a MonitoringRoleArn
    # for — so validate it at the boundary rather than deferring to _modify_monitoring.
    monitoring_role_arn = _optional_str(event.get("MonitoringRoleArn", ""))
    if not monitoring_role_arn:
        raise ValueError("MonitoringRoleArn is required to enable enhanced monitoring.")
    return CaptureAndRemediateEvent(
        RDSInstanceARN=rds_instance_arn,
        AccountId=account_id,
        RemediationConfigBucket=_optional_str(event.get("RemediationConfigBucket", "")),
        AutomationExecutionId=_optional_str(event.get("AutomationExecutionId", "")),
        MonitoringInterval=target_interval,
        MonitoringRoleArn=monitoring_role_arn,
        ApplyImmediately=_validate_apply_immediately(
            event.get("ApplyImmediately", "true")
        ),
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    # Common fields validated by the shared helper; only the instance ARN + ApplyImmediately are control-specific.
    common = validate_common_rollback_fields(event)
    return ExecuteRollbackEvent(
        RDSInstanceARN=_validate_instance_arn(event, common["AccountId"]),
        AccountId=common["AccountId"],
        RemediationConfigBucket=common["RemediationConfigBucket"],
        ExecutionId=common["ExecutionId"],
        SnapshotVersionId=common["SnapshotVersionId"],
        ApplyImmediately=_validate_apply_immediately(
            event.get("ApplyImmediately", "true")
        ),
    )


def capture_and_remediate(event: dict[str, object], _context: object) -> CaptureResult:
    validated = _validate_capture_event(event)
    rds_instance_arn = validated["RDSInstanceARN"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]
    target_interval = validated["MonitoringInterval"]
    target_role = validated["MonitoringRoleArn"]
    apply_immediately = validated["ApplyImmediately"]
    db_instance_id = _instance_id_from_arn(rds_instance_arn)

    rds: RDSClient = boto3.client("rds", config=ROLLBACK_BOTO_CONFIG)
    current_interval, current_role, can_capture_snapshot = _read_pre_state(
        rds, db_instance_id
    )

    # No-op only when we could read the state AND it already matches the exact target (interval AND role).
    # Gated on can_capture_snapshot so a fail-open read can't false-trigger a "no remediation needed".
    if can_capture_snapshot and _monitoring_state_key(
        current_interval, current_role
    ) == _monitoring_state_key(target_interval, target_role):
        logger.info(
            "Enhanced monitoring already at target; no remediation needed",
            extra={"dbInstanceId": db_instance_id, "interval": target_interval},
        )
        return {
            "snapshotStored": "false",
            "snapshotVersionId": "",
            "rollbackDescription": f"No remediation needed: enhanced monitoring was already at interval {target_interval}.",
        }

    # Snapshot the pre-remediation state before remediating (fail-open). Skipped if the pre-state read failed.
    # If the enable below fails, the SSM step fails and the Orchestrator never marks the execution
    # rollbackAvailable, so an orphaned snapshot is cleaned up by the S3 lifecycle rule and never used.
    is_snapshot_stored, snapshot_version_id = (
        capture_snapshot(
            bucket,
            execution_id=execution_id,
            account_id=validated["AccountId"],
            resource_id=rds_instance_arn,
            control_id=CONTROL_ID,
            pre_state={
                "MonitoringInterval": current_interval,
                "MonitoringRoleArn": current_role,
            },
            post_state={
                "MonitoringInterval": target_interval,
                "MonitoringRoleArn": target_role,
            },
        )
        if can_capture_snapshot
        else (False, "")
    )

    _modify_monitoring(
        rds,
        db_instance_id,
        interval=target_interval,
        role=target_role,
        apply_immediately=apply_immediately,
    )
    # Confirm the change settled and took effect (enhanced monitoring is applied asynchronously).
    _wait_and_verify_state(
        rds,
        db_instance_id,
        expected_interval=target_interval,
        expected_role=target_role,
    )
    logger.info(
        "Enhanced monitoring enabled",
        extra={"dbInstanceId": db_instance_id, "interval": target_interval},
    )

    is_stored = bool(is_snapshot_stored and snapshot_version_id)
    rollback_description = (
        f"Restore enhanced monitoring interval to {current_interval} for RDS instance {db_instance_id}"
        if is_stored
        else "Rollback unavailable: pre-remediation state was not captured."
    )
    return {
        "snapshotStored": "true" if is_stored else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": rollback_description,
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    validated = _validate_rollback_event(event)
    rds_instance_arn = validated["RDSInstanceARN"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["ExecutionId"]
    snapshot_version_id = validated["SnapshotVersionId"]
    apply_immediately = validated["ApplyImmediately"]
    db_instance_id = _instance_id_from_arn(rds_instance_arn)

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

    # Verify the snapshot belongs to the instance being rolled back (guards against an execution id
    # resolving to another resource's snapshot).
    snapshot_resource_id = snapshot.get("resourceId")
    if snapshot_resource_id != rds_instance_arn:
        raise SnapshotValidationError(
            f"Rollback aborted for instance {db_instance_id}: snapshot resourceId ({snapshot_resource_id!r}) "
            f"does not match the target instance ARN ({rds_instance_arn!r})."
        )

    original_state = get_pre_remediation_state(snapshot, execution_id)
    original_interval = _require_interval(
        original_state.get("MonitoringInterval"),
        execution_id=execution_id,
        state_label="preRemediationState",
    )
    original_role = _optional_str(original_state.get("MonitoringRoleArn"))

    post_state = get_post_remediation_state(snapshot, execution_id)
    post_interval = _require_interval(
        post_state.get("MonitoringInterval"),
        execution_id=execution_id,
        state_label="postRemediationState",
    )
    post_role = _optional_str(post_state.get("MonitoringRoleArn"))

    rds: RDSClient = boto3.client("rds", config=ROLLBACK_BOTO_CONFIG)
    current_interval, current_role = _get_monitoring_state(rds, db_instance_id)

    # Decide the outcome from the (interval, role) state. The role is normalized to "" at interval 0 (see
    # _monitoring_state_key) so a completed rollback to a disabled state is an idempotent no-op, not drift.
    action = resolve_rollback_action(
        _monitoring_state_key(current_interval, current_role),
        _monitoring_state_key(original_interval, original_role),
        _monitoring_state_key(post_interval, post_role),
    )
    if action is RollbackAction.NOOP:
        return {
            "Message": f"Instance {db_instance_id} is already in its pre-remediation state. No rollback action needed.",
            "Status": "SUCCESS",
        }
    if action is RollbackAction.DRIFT:
        raise SnapshotValidationError(
            f"Rollback aborted for instance {db_instance_id}: current monitoring state "
            f"(interval={current_interval}, role={current_role!r}) does not match the post-remediation state "
            f"ASR applied (interval={post_interval}, role={post_role!r}). The resource was modified after the ASR remediation."
        )

    _modify_monitoring(
        rds,
        db_instance_id,
        interval=original_interval,
        role=original_role,
        apply_immediately=apply_immediately,
    )
    # Confirm the restore settled and took effect (same asynchronous behavior as the forward remediation).
    _wait_and_verify_state(
        rds,
        db_instance_id,
        expected_interval=original_interval,
        expected_role=original_role,
    )
    logger.info(
        "Enhanced monitoring interval restored (rollback)",
        extra={"dbInstanceId": db_instance_id, "interval": original_interval},
    )
    return {
        "Message": f"Successfully restored monitoring interval to {original_interval} for RDS instance {db_instance_id}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    return dispatch_rollback_handler(
        event, context, capture_fn=capture_and_remediate, rollback_fn=execute_rollback
    )
