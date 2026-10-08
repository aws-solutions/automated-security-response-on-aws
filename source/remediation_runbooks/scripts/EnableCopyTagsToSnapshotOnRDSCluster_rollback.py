# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""RDS.16 — EnableCopyTagsToSnapshotOnRDSCluster rollback script (shared rollback framework).

capture_and_remediate is fail-open (a snapshot failure never blocks remediation); execute_rollback
is fail-closed (any safety-gate failure aborts, raising RuntimeError so SSM reports ROLLBACK_FAILED).
State is the cluster's CopyTagsToSnapshot flag (bool).
"""
from __future__ import annotations

import logging
from typing import Any, Protocol, TypedDict

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

CONTROL_ID = "RDS.16"

_CLUSTER_ARN_MARKER = ":cluster:"
_VALID_PARTITIONS = ("aws", "aws-cn", "aws-us-gov")
_INVALID_CLUSTER_ARN_MESSAGE = (
    "Missing or invalid required parameter: RDSClusterARN (expected an RDS cluster ARN)"
)


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
    def describe_db_clusters(
        self, *, DBClusterIdentifier: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def modify_db_cluster(
        self,
        *,
        DBClusterIdentifier: str,
        CopyTagsToSnapshot: bool,
        ApplyImmediately: bool,
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names


class CaptureAndRemediateEvent(TypedDict):
    RDSClusterARN: str
    AccountId: str
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str
    ApplyImmediately: bool


class ExecuteRollbackEvent(TypedDict):
    RDSClusterARN: str
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str
    ApplyImmediately: bool


def _validate_cluster_arn(event: dict[str, object], account_id: str) -> str:
    """Validate the RDS cluster ARN and confirm its account matches account_id (defense-in-depth
    against operating on a cross-account cluster)."""
    parsed = _parse_arn(event.get("RDSClusterARN"))
    if parsed is None:
        raise ValueError(_INVALID_CLUSTER_ARN_MESSAGE)
    cluster_arn, parts = parsed
    if (
        parts[2] != "rds"
        or not parts[3]
        or not parts[4].isdigit()
        or len(parts[4]) != 12
        or not parts[5].startswith("cluster:")
    ):
        raise ValueError(_INVALID_CLUSTER_ARN_MESSAGE)
    if not cluster_arn.split(_CLUSTER_ARN_MARKER, 1)[1]:
        raise ValueError(_INVALID_CLUSTER_ARN_MESSAGE)
    if parts[4] != account_id:
        raise ValueError(
            f"RDSClusterARN account ({parts[4]}) does not match the executing account ({account_id}); "
            f"refusing to operate on a cross-account cluster."
        )
    return cluster_arn


def _cluster_id_from_arn(cluster_arn: str) -> str:
    return cluster_arn.split(_CLUSTER_ARN_MARKER, 1)[1]


def _get_copy_tags(rds: RDSClient, cluster_id: str) -> bool:
    try:
        clusters = rds.describe_db_clusters(DBClusterIdentifier=cluster_id).get(
            "DBClusters", []
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
            raise ResourceNotFoundError(
                f"RDS DB cluster {cluster_id} not found."
            ) from error
        raise
    if not clusters:
        raise ResourceNotFoundError(f"RDS DB cluster {cluster_id} not found.")
    return bool(clusters[0].get("CopyTagsToSnapshot", False))


def _read_pre_state(rds: RDSClient, cluster_id: str) -> tuple[bool, bool]:
    """Fail-open read of CopyTagsToSnapshot. Returns (enabled, can_capture_snapshot); on error
    returns (False, False) — snapshot skipped, remediation still proceeds. First value is
    meaningless unless the second is True."""
    try:
        return _get_copy_tags(rds, cluster_id), True
    except (ClientError, BotoCoreError):
        logger.exception(
            "Pre-remediation state read failed (fail-open); skipping snapshot",
            extra={"clusterId": cluster_id},
        )
        return False, False


def _validate_pre_copy_tags(snapshot: dict[str, Any], execution_id: str) -> bool:
    # Require a real bool so a malformed snapshot fails closed rather than being coerced.
    pre_state = get_pre_remediation_state(snapshot, execution_id)
    value = pre_state.get("CopyTagsToSnapshot")
    if not isinstance(value, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'preRemediationState.CopyTagsToSnapshot'."
        )
    return value


def _validate_post_copy_tags(snapshot: dict[str, Any], execution_id: str) -> bool:
    post_state = get_post_remediation_state(snapshot, execution_id)
    value = post_state.get("CopyTagsToSnapshot")
    if not isinstance(value, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'postRemediationState.CopyTagsToSnapshot'."
        )
    return value


def _optional_str(event: dict[str, object], name: str) -> str:
    # Guard fail-open capture fields: a non-string (e.g. None from SSM) becomes "" (skip snapshot), not "None".
    value = event.get(name)
    return value if isinstance(value, str) else ""


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
    cluster_arn = _validate_cluster_arn(event, account_id)
    return CaptureAndRemediateEvent(
        RDSClusterARN=cluster_arn,
        AccountId=account_id,
        RemediationConfigBucket=_optional_str(event, "RemediationConfigBucket"),
        AutomationExecutionId=_optional_str(event, "AutomationExecutionId"),
        ApplyImmediately=str(event.get("ApplyImmediately", "false")).lower() == "true",
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    # Common fields validated by the shared helper; only the cluster ARN + ApplyImmediately are control-specific.
    common = validate_common_rollback_fields(event)
    cluster_arn = _validate_cluster_arn(event, common["AccountId"])
    return ExecuteRollbackEvent(
        RDSClusterARN=cluster_arn,
        AccountId=common["AccountId"],
        RemediationConfigBucket=common["RemediationConfigBucket"],
        ExecutionId=common["ExecutionId"],
        SnapshotVersionId=common["SnapshotVersionId"],
        ApplyImmediately=str(event.get("ApplyImmediately", "false")).lower() == "true",
    )


def capture_and_remediate(event: dict[str, object], _context: object) -> CaptureResult:
    """Fail-open capture: a snapshot read/write failure never blocks the security remediation."""
    validated = _validate_capture_event(event)
    cluster_arn = validated["RDSClusterARN"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]
    apply_immediately = validated["ApplyImmediately"]
    cluster_id = _cluster_id_from_arn(cluster_arn)

    rds: RDSClient = boto3.client("rds", config=ROLLBACK_BOTO_CONFIG)

    is_currently_enabled, can_capture_snapshot = _read_pre_state(rds, cluster_id)

    # No-op: already enabled (pre == post). Gated on can_capture_snapshot so a fail-open read can't
    # false-trigger it. Skip the snapshot (avoids a misleading no-op rollback); idempotent modify still runs.
    if can_capture_snapshot and is_currently_enabled:
        rds.modify_db_cluster(
            DBClusterIdentifier=cluster_id,
            CopyTagsToSnapshot=True,
            ApplyImmediately=apply_immediately,
        )
        logger.info(
            "CopyTagsToSnapshot already enabled; no remediation needed, snapshot skipped",
            extra={"clusterId": cluster_id},
        )
        return {
            "snapshotStored": "false",
            "snapshotVersionId": "",
            "rollbackDescription": "No remediation needed: CopyTagsToSnapshot was already enabled.",
        }

    is_snapshot_stored, snapshot_version_id = (
        capture_snapshot(
            bucket,
            execution_id=execution_id,
            account_id=account_id,
            resource_id=cluster_arn,
            control_id=CONTROL_ID,
            pre_state={"CopyTagsToSnapshot": is_currently_enabled},
            # Intended post-state, written pre-remediation. Guarantees pre != post (so rollback can
            # distinguish drift); a failed remediation leaves an inert orphan snapshot that's never used.
            post_state={"CopyTagsToSnapshot": True},
        )
        if can_capture_snapshot
        else (False, "")
    )

    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id,
        CopyTagsToSnapshot=True,
        ApplyImmediately=apply_immediately,
    )
    logger.info("CopyTagsToSnapshot enabled", extra={"clusterId": cluster_id})

    if not is_snapshot_stored:
        rollback_description = (
            "Rollback unavailable: pre-remediation state was not captured."
        )
    else:
        rollback_description = (
            f"Disable CopyTagsToSnapshot for RDS cluster {cluster_id}"
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
    cluster_arn = validated["RDSClusterARN"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["ExecutionId"]
    snapshot_version_id = validated["SnapshotVersionId"]
    apply_immediately = validated["ApplyImmediately"]
    cluster_id = _cluster_id_from_arn(cluster_arn)

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

    was_originally_enabled = _validate_pre_copy_tags(snapshot, execution_id)
    was_post_remediation_enabled = _validate_post_copy_tags(snapshot, execution_id)

    rds: RDSClient = boto3.client("rds", config=ROLLBACK_BOTO_CONFIG)
    is_currently_enabled = _get_copy_tags(rds, cluster_id)

    action = resolve_rollback_action(
        is_currently_enabled, was_originally_enabled, was_post_remediation_enabled
    )
    if action is RollbackAction.NOOP:
        return {
            "Message": f"Cluster {cluster_id} is already in its pre-remediation state. No rollback action needed.",
            "Status": "SUCCESS",
        }
    if action is RollbackAction.DRIFT:
        raise SnapshotValidationError(
            f"Rollback aborted for cluster {cluster_id}: current CopyTagsToSnapshot ({is_currently_enabled}) "
            f"does not match the post-remediation state ASR applied ({was_post_remediation_enabled}). "
            f"The resource was modified after the ASR remediation."
        )

    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id,
        CopyTagsToSnapshot=was_originally_enabled,
        ApplyImmediately=apply_immediately,
    )
    logger.info(
        "CopyTagsToSnapshot restored (rollback)", extra={"clusterId": cluster_id}
    )
    return {
        "Message": f"Successfully restored CopyTagsToSnapshot to {was_originally_enabled} for cluster {cluster_id}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    return dispatch_rollback_handler(
        event, context, capture_fn=capture_and_remediate, rollback_fn=execute_rollback
    )
