# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""RDS.13 — EnableMinorVersionUpgradeOnRDSDBInstance rollback script (shared rollback framework).

capture_and_remediate is fail-open (a snapshot failure never blocks remediation); execute_rollback
is fail-closed (any safety-gate failure aborts, raising RuntimeError so SSM reports ROLLBACK_FAILED).
State is AutoMinorVersionUpgrade (bool). Like the forward remediation, the setting is applied on the
Multi-AZ cluster when the instance belongs to one (mysql/postgres), otherwise on the instance itself;
the same resolution runs at capture and rollback so the setting is read/restored on the same target.
"""
from __future__ import annotations

import logging
from typing import Any, Literal, NamedTuple, Protocol, TypedDict

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

CONTROL_ID = "RDS.13"

_INSTANCE_ARN_MARKER = ":db:"
_VALID_PARTITIONS = ("aws", "aws-cn", "aws-us-gov")
_INVALID_INSTANCE_ARN_MESSAGE = "Missing or invalid required parameter: RDSInstanceARN (expected an RDS DB instance ARN)"
_MULTI_AZ_CLUSTER_ENGINES = ("mysql", "postgres")

TargetKind = Literal["cluster", "instance"]
_TARGET_CLUSTER: TargetKind = "cluster"
_TARGET_INSTANCE: TargetKind = "instance"


class ModifyTarget(NamedTuple):
    """The resolved (cluster vs instance) point where AutoMinorVersionUpgrade is read/modified."""

    kind: TargetKind
    identifier: str


class RemediationVerificationError(RollbackError):
    """The remediation modify call succeeded but verification showed AutoMinorVersionUpgrade did not persist."""


def _parse_arn(value: object) -> tuple[str, list[str]] | None:
    """Return (arn, segments) for a structurally valid 6-segment ARN with a known partition, else None
    (so a lookalike string can't pass a substring check)."""
    if not isinstance(value, str):
        return None
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[1] not in _VALID_PARTITIONS:
        return None
    return value, parts


class RDSClient(Protocol):
    # Parameter names mirror the boto3 RDS API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def describe_db_instances(
        self, *, DBInstanceIdentifier: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def describe_db_clusters(
        self, *, DBClusterIdentifier: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def modify_db_instance(
        self, *, DBInstanceIdentifier: str, AutoMinorVersionUpgrade: bool
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names

    def modify_db_cluster(
        self, *, DBClusterIdentifier: str, AutoMinorVersionUpgrade: bool
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names


class CaptureAndRemediateEvent(TypedDict):
    RDSInstanceARN: str
    AccountId: str
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str


class ExecuteRollbackEvent(TypedDict):
    RDSInstanceARN: str
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str


def _validate_instance_arn(event: dict[str, object], account_id: str) -> str:
    """Validate the RDS DB instance ARN and confirm its account matches account_id (defense-in-depth
    against operating on a cross-account instance)."""
    parsed = _parse_arn(event.get("RDSInstanceARN"))
    if parsed is None:
        raise ValueError(_INVALID_INSTANCE_ARN_MESSAGE)
    instance_arn, parts = parsed
    is_rds_service = parts[2] == "rds"
    has_region = bool(parts[3])
    is_valid_account = parts[4].isdigit() and len(parts[4]) == 12
    is_db_resource = parts[5].startswith("db:")
    if not (is_rds_service and has_region and is_valid_account and is_db_resource):
        raise ValueError(_INVALID_INSTANCE_ARN_MESSAGE)
    if not instance_arn.split(_INSTANCE_ARN_MARKER, 1)[1]:
        raise ValueError(_INVALID_INSTANCE_ARN_MESSAGE)
    if parts[4] != account_id:
        raise ValueError(
            f"RDSInstanceARN account ({parts[4]}) does not match the executing account ({account_id}); "
            f"refusing to operate on a cross-account instance."
        )
    return instance_arn


def _instance_id_from_arn(instance_arn: str) -> str:
    return instance_arn.split(_INSTANCE_ARN_MARKER, 1)[1]


def _optional_str(event: dict[str, object], name: str) -> str:
    # Guard fail-open capture fields: a non-string (e.g. None from SSM) becomes "" (skip snapshot), not "None".
    value = event.get(name)
    return value if isinstance(value, str) else ""


def _describe_one(
    rds: RDSClient, *, kind: TargetKind, identifier: str
) -> dict[str, Any]:
    """Describe a single cluster or instance, mapping the service's not-found code to ResourceNotFoundError."""
    not_found_code = (
        "DBClusterNotFoundFault" if kind == _TARGET_CLUSTER else "DBInstanceNotFound"
    )
    try:
        if kind == _TARGET_CLUSTER:
            items = rds.describe_db_clusters(DBClusterIdentifier=identifier).get(
                "DBClusters", []
            )
        else:
            items = rds.describe_db_instances(DBInstanceIdentifier=identifier).get(
                "DBInstances", []
            )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == not_found_code:
            raise ResourceNotFoundError(
                f"RDS DB {kind} {identifier} not found."
            ) from error
        raise
    if not items:
        raise ResourceNotFoundError(f"RDS DB {kind} {identifier} not found.")
    return items[0]


def _is_multi_az_db_cluster(cluster: dict[str, Any]) -> bool:
    """Whether the instance's cluster is a Multi-AZ DB cluster the remediation modifies at the cluster
    level (MultiAZ with a mysql/postgres engine), mirroring the forward remediation's multi_az_check.
    """
    return (
        bool(cluster.get("MultiAZ"))
        and cluster.get("Engine") in _MULTI_AZ_CLUSTER_ENGINES
    )


def _resolve_target(rds: RDSClient, db_instance_id: str) -> ModifyTarget:
    """Resolve the modification target the same way the forward remediation does: the Multi-AZ cluster
    (mysql/postgres) the instance belongs to, else the instance itself."""
    instance = _describe_one(rds, kind=_TARGET_INSTANCE, identifier=db_instance_id)
    cluster_id = instance.get("DBClusterIdentifier")
    if isinstance(cluster_id, str) and cluster_id:
        cluster = _describe_one(rds, kind=_TARGET_CLUSTER, identifier=cluster_id)
        if _is_multi_az_db_cluster(cluster):
            return ModifyTarget(_TARGET_CLUSTER, cluster_id)
    return ModifyTarget(_TARGET_INSTANCE, db_instance_id)


def _get_auto_minor_version_upgrade(rds: RDSClient, target: ModifyTarget) -> bool:
    return bool(
        _describe_one(rds, kind=target.kind, identifier=target.identifier).get(
            "AutoMinorVersionUpgrade", False
        )
    )


def _set_auto_minor_version_upgrade(
    rds: RDSClient, target: ModifyTarget, *, enabled: bool
) -> None:
    if target.kind == _TARGET_CLUSTER:
        rds.modify_db_cluster(
            DBClusterIdentifier=target.identifier, AutoMinorVersionUpgrade=enabled
        )
    else:
        rds.modify_db_instance(
            DBInstanceIdentifier=target.identifier, AutoMinorVersionUpgrade=enabled
        )


def _verify_state(rds: RDSClient, target: ModifyTarget, *, expected: bool) -> None:
    # AutoMinorVersionUpgrade applies immediately, so confirm the modify took effect before reporting
    # success — on both the forward path (expected=True) and the rollback path (expected=the
    # pre-remediation value). A silent non-persist must not be reported as success.
    if _get_auto_minor_version_upgrade(rds, target) != expected:
        raise RemediationVerificationError(
            f"AutoMinorVersionUpgrade did not reach the expected state ({expected}) on RDS {target.kind} {target.identifier}."
        )


def _read_pre_state(rds: RDSClient, target: ModifyTarget) -> tuple[bool, bool]:
    """Fail-open read of AutoMinorVersionUpgrade. Returns (enabled, can_capture_snapshot); on a transient
    error returns (False, False) — snapshot skipped, remediation still proceeds. The first value is
    meaningless unless the second is True."""
    try:
        return _get_auto_minor_version_upgrade(rds, target), True
    except (ClientError, BotoCoreError):
        logger.exception(
            "Pre-remediation state read failed (fail-open); skipping snapshot",
            extra={"target": target},
        )
        return False, False


def _validate_pre_auto_minor_version_upgrade(
    snapshot: dict[str, Any], execution_id: str
) -> bool:
    # Require a real bool so a malformed snapshot fails closed rather than being coerced.
    value = get_pre_remediation_state(snapshot, execution_id).get(
        "AutoMinorVersionUpgrade"
    )
    if not isinstance(value, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'preRemediationState.AutoMinorVersionUpgrade'."
        )
    return value


def _validate_post_auto_minor_version_upgrade(
    snapshot: dict[str, Any], execution_id: str
) -> bool:
    value = get_post_remediation_state(snapshot, execution_id).get(
        "AutoMinorVersionUpgrade"
    )
    if not isinstance(value, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'postRemediationState.AutoMinorVersionUpgrade'."
        )
    return value


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
    instance_arn = _validate_instance_arn(event, account_id)
    return CaptureAndRemediateEvent(
        RDSInstanceARN=instance_arn,
        AccountId=account_id,
        RemediationConfigBucket=_optional_str(event, "RemediationConfigBucket"),
        AutomationExecutionId=_optional_str(event, "AutomationExecutionId"),
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    # Common fields validated by the shared helper; only the instance ARN is control-specific.
    common = validate_common_rollback_fields(event)
    return ExecuteRollbackEvent(
        RDSInstanceARN=_validate_instance_arn(event, common["AccountId"]),
        AccountId=common["AccountId"],
        RemediationConfigBucket=common["RemediationConfigBucket"],
        ExecutionId=common["ExecutionId"],
        SnapshotVersionId=common["SnapshotVersionId"],
    )


def capture_and_remediate(event: dict[str, object], _context: object) -> CaptureResult:
    """Fail-open capture: a snapshot read/write failure never blocks the security remediation."""
    validated = _validate_capture_event(event)
    instance_arn = validated["RDSInstanceARN"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]
    db_instance_id = _instance_id_from_arn(instance_arn)

    rds: RDSClient = boto3.client("rds", config=ROLLBACK_BOTO_CONFIG)
    target = _resolve_target(rds, db_instance_id)
    is_currently_enabled, can_capture_snapshot = _read_pre_state(rds, target)

    # No-op: already enabled (pre == post). Gated on can_capture_snapshot so a fail-open read can't
    # false-trigger it. Skip the snapshot (avoids a misleading no-op rollback); idempotent modify still runs.
    if can_capture_snapshot and is_currently_enabled:
        _set_auto_minor_version_upgrade(rds, target, enabled=True)
        logger.info(
            "AutoMinorVersionUpgrade already enabled; no remediation needed, snapshot skipped",
            extra={"target": target},
        )
        return {
            "snapshotStored": "false",
            "snapshotVersionId": "",
            "rollbackDescription": "No remediation needed: AutoMinorVersionUpgrade was already enabled.",
        }

    is_snapshot_stored, snapshot_version_id = (
        capture_snapshot(
            bucket,
            execution_id=execution_id,
            account_id=validated["AccountId"],
            resource_id=instance_arn,
            control_id=CONTROL_ID,
            pre_state={"AutoMinorVersionUpgrade": is_currently_enabled},
            # Intended post-state, written pre-remediation. Guarantees pre != post (so rollback can
            # distinguish drift); a failed remediation leaves an inert orphan snapshot that's never used.
            post_state={"AutoMinorVersionUpgrade": True},
        )
        if can_capture_snapshot
        else (False, "")
    )

    _set_auto_minor_version_upgrade(rds, target, enabled=True)
    _verify_state(rds, target, expected=True)
    logger.info("AutoMinorVersionUpgrade enabled", extra={"target": target})

    if not is_snapshot_stored:
        rollback_description = (
            "Rollback unavailable: pre-remediation state was not captured."
        )
    else:
        rollback_description = (
            f"Disable AutoMinorVersionUpgrade for RDS {target.kind} {target.identifier}"
        )
    return {
        "snapshotStored": "true" if is_snapshot_stored else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": rollback_description,
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    """Fail-closed rollback: reads the snapshot by its recorded version id (tamper-proof) and aborts
    on drift, so a state the operator set after remediation is never overwritten."""
    validated = _validate_rollback_event(event)
    instance_arn = validated["RDSInstanceARN"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["ExecutionId"]
    snapshot_version_id = validated["SnapshotVersionId"]
    db_instance_id = _instance_id_from_arn(instance_arn)

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

    was_originally_enabled = _validate_pre_auto_minor_version_upgrade(
        snapshot, execution_id
    )
    was_post_remediation_enabled = _validate_post_auto_minor_version_upgrade(
        snapshot, execution_id
    )

    rds: RDSClient = boto3.client("rds", config=ROLLBACK_BOTO_CONFIG)
    target = _resolve_target(rds, db_instance_id)
    is_currently_enabled = _get_auto_minor_version_upgrade(rds, target)

    action = resolve_rollback_action(
        is_currently_enabled, was_originally_enabled, was_post_remediation_enabled
    )
    if action is RollbackAction.NOOP:
        return {
            "Message": f"RDS {target.kind} {target.identifier} is already in its pre-remediation state. No rollback action needed.",
            "Status": "SUCCESS",
        }
    if action is RollbackAction.DRIFT:
        raise SnapshotValidationError(
            f"Rollback aborted for RDS {target.kind} {target.identifier}: current AutoMinorVersionUpgrade "
            f"({is_currently_enabled}) does not match the post-remediation state ASR applied "
            f"({was_post_remediation_enabled}). The resource was modified after the ASR remediation."
        )

    _set_auto_minor_version_upgrade(rds, target, enabled=was_originally_enabled)
    _verify_state(rds, target, expected=was_originally_enabled)
    logger.info("AutoMinorVersionUpgrade restored (rollback)", extra={"target": target})
    return {
        "Message": f"Successfully restored AutoMinorVersionUpgrade to {was_originally_enabled} for RDS {target.kind} {target.identifier}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    return dispatch_rollback_handler(
        event, context, capture_fn=capture_and_remediate, rollback_fn=execute_rollback
    )
