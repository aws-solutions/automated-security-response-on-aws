# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""RDS.7 — EnableRDSClusterDeletionProtection rollback script.

Handlers:
  capture_and_remediate: Captures the pre-remediation DeletionProtection
      state to S3, then enables it. Fail-open: if snapshot write fails,
      remediation still proceeds.
  execute_rollback: Reads and validates the snapshot from S3, and if the
      cluster is still in the post-remediation state, restores the original
      setting.

Rollback failures raise RuntimeError so SSM Automation marks the step Failed,
which the orchestrator reports as ROLLBACK_FAILED.
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
    RollbackError,
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

CONTROL_ID = "RDS.7"

# Standard-mode retries so transient RDS throttling does not spuriously fail the step.
BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


class RDSClient(Protocol):
    # Parameter names mirror the boto3 RDS API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def describe_db_clusters(
        self, *, DBClusterIdentifier: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def modify_db_cluster(
        self,
        *,
        DBClusterIdentifier: str,
        DeletionProtection: bool,
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


class CaptureResult(TypedDict):
    snapshotStored: Literal["true", "false"]
    snapshotVersionId: str
    rollbackDescription: str


class RollbackResult(TypedDict):
    Message: str
    Status: Literal["SUCCESS"]


class HandlerResult(TypedDict):
    """Unified dispatch payload: every declared SSM output key is always present so the collapsed
    SnapshotRemediateOrRollback step's output selectors resolve on both the remediation and rollback paths.
    """

    snapshotStored: Literal["true", "false", ""]
    snapshotVersionId: str
    rollbackDescription: str
    Message: str
    Status: Literal["SUCCESS", ""]


class ClusterNotFoundError(RollbackError):
    """The target RDS DB cluster no longer exists."""


_CLUSTER_ARN_MARKER = ":cluster:"


def _validate_cluster_arn(event: dict[str, object]) -> str:
    rds_cluster_arn = event.get("RDSClusterARN")
    if (
        not isinstance(rds_cluster_arn, str)
        or not rds_cluster_arn.startswith("arn:")
        or _CLUSTER_ARN_MARKER not in rds_cluster_arn
        or not rds_cluster_arn.split(_CLUSTER_ARN_MARKER, 1)[1]
    ):
        raise ValueError(
            "Missing or invalid required parameter: RDSClusterARN (expected an RDS DB cluster ARN)"
        )
    return rds_cluster_arn


def _db_cluster_id_from_arn(rds_cluster_arn: str) -> str:
    return rds_cluster_arn.split(_CLUSTER_ARN_MARKER, 1)[1]


def _get_deletion_protection(rds: RDSClient, db_cluster_id: str) -> bool:
    try:
        clusters = rds.describe_db_clusters(DBClusterIdentifier=db_cluster_id).get(
            "DBClusters", []
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
            raise ClusterNotFoundError(
                f"RDS DB cluster {db_cluster_id} not found."
            ) from error
        raise
    if not clusters:
        raise ClusterNotFoundError(f"RDS DB cluster {db_cluster_id} not found.")
    return bool(clusters[0].get("DeletionProtection", False))


def _read_pre_remediation_state(snapshot: dict[str, Any], execution_id: str) -> bool:
    pre_state = get_pre_remediation_state(snapshot, execution_id)
    is_enabled = pre_state.get("DeletionProtection")
    if not isinstance(is_enabled, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'preRemediationState.DeletionProtection'."
        )
    return is_enabled


def _read_post_remediation_state(snapshot: dict[str, Any], execution_id: str) -> bool:
    post_state = get_post_remediation_state(snapshot, execution_id)
    is_enabled = post_state.get("DeletionProtection")
    if not isinstance(is_enabled, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'postRemediationState.DeletionProtection'."
        )
    return is_enabled


def _validate_capture_event(event: dict[str, object]) -> CaptureAndRemediateEvent:
    rds_cluster_arn = _validate_cluster_arn(event)
    account_id = event.get("AccountId")
    if not isinstance(account_id, str) or not account_id:
        raise ValueError("Missing required parameter: AccountId")
    return CaptureAndRemediateEvent(
        RDSClusterARN=rds_cluster_arn,
        AccountId=account_id,
        RemediationConfigBucket=str(event.get("RemediationConfigBucket", "")),
        AutomationExecutionId=str(event.get("AutomationExecutionId", "")),
        ApplyImmediately=str(event.get("ApplyImmediately", "false")).lower() == "true",
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    rds_cluster_arn = _validate_cluster_arn(event)
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
        RDSClusterARN=rds_cluster_arn,
        AccountId=validated["AccountId"],
        RemediationConfigBucket=validated["RemediationConfigBucket"],
        ExecutionId=validated["ExecutionId"],
        SnapshotVersionId=snapshot_version_id,
        ApplyImmediately=str(event.get("ApplyImmediately", "false")).lower() == "true",
    )


def _capture_snapshot(
    bucket: str,
    *,
    execution_id: str,
    account_id: str,
    resource_arn: str,
    was_deletion_protection_enabled: bool,
) -> tuple[bool, str]:
    if not bucket or not execution_id:
        logger.warning(
            "Snapshot skipped: missing bucket or execution ID",
            extra={"bucket": bucket, "executionId": execution_id},
        )
        return False, ""
    # postRemediationState is the state ASR *applies* (enabled), not a re-read. DeletionProtection is
    # not a deferrable setting (it never appears in PendingModifiedValues), so it takes effect
    # immediately regardless of ApplyImmediately and the drift check (current vs post) holds.
    snapshot_data = build_snapshot(
        resource_arn,
        CONTROL_ID,
        {"DeletionProtection": was_deletion_protection_enabled},
        {"DeletionProtection": True},
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
    validated = _validate_capture_event(event)
    rds_cluster_arn = validated["RDSClusterARN"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]
    apply_immediately = validated["ApplyImmediately"]
    db_cluster_id = _db_cluster_id_from_arn(rds_cluster_arn)

    rds: RDSClient = boto3.client("rds", config=BOTO_CONFIG)
    is_currently_enabled = _get_deletion_protection(rds, db_cluster_id)

    # Snapshot-first (per design): capture the pre-remediation state to S3 BEFORE remediating.
    # If the enable below fails, the SSM step fails and the Orchestrator never marks the execution
    # rollbackAvailable (rollback is offered only for successful remediations), so an orphaned
    # snapshot is cleaned up by the S3 lifecycle rule and never used for a rollback/drift check.
    is_snapshot_stored, snapshot_version_id = _capture_snapshot(
        bucket,
        execution_id=execution_id,
        account_id=account_id,
        resource_arn=rds_cluster_arn,
        was_deletion_protection_enabled=is_currently_enabled,
    )

    if not is_currently_enabled:
        rds.modify_db_cluster(
            DBClusterIdentifier=db_cluster_id,
            DeletionProtection=True,
            ApplyImmediately=apply_immediately,
        )
        logger.info("Deletion protection enabled", extra={"dbClusterId": db_cluster_id})
    else:
        logger.info(
            "Deletion protection already enabled; no change needed",
            extra={"dbClusterId": db_cluster_id},
        )

    rollback_description = (
        f"Disable deletion protection for RDS cluster {db_cluster_id}"
        if not is_currently_enabled
        else f"Deletion protection was already enabled for RDS cluster {db_cluster_id} (no-op rollback)"
    )
    is_snapshot_available = is_snapshot_stored and bool(snapshot_version_id)
    return {
        "snapshotStored": "true" if is_snapshot_available else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": rollback_description,
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    validated = _validate_rollback_event(event)
    rds_cluster_arn = validated["RDSClusterARN"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["ExecutionId"]
    snapshot_version_id = validated["SnapshotVersionId"]
    apply_immediately = validated["ApplyImmediately"]
    db_cluster_id = _db_cluster_id_from_arn(rds_cluster_arn)

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

    # Verify the snapshot belongs to the cluster being rolled back, so we restore state for the
    # resource we read it for (guards against an execution id resolving to another resource's snapshot).
    snapshot_resource_id = snapshot.get("resourceId")
    if snapshot_resource_id != rds_cluster_arn:
        raise SnapshotValidationError(
            f"Rollback aborted for cluster {db_cluster_id}: snapshot resourceId ({snapshot_resource_id!r}) "
            f"does not match the target cluster ARN ({rds_cluster_arn!r})."
        )

    was_originally_enabled = _read_pre_remediation_state(snapshot, execution_id)
    post_remediation_enabled = _read_post_remediation_state(snapshot, execution_id)

    rds: RDSClient = boto3.client("rds", config=BOTO_CONFIG)
    is_currently_enabled = _get_deletion_protection(rds, db_cluster_id)

    # Drift check: the resource must still be in the post-remediation state ASR applied. If it has
    # changed since remediation, someone modified it afterward — abort the rollback and surface the drift.
    if is_currently_enabled != post_remediation_enabled:
        raise SnapshotValidationError(
            f"Rollback aborted for cluster {db_cluster_id}: current deletion protection ({is_currently_enabled}) "
            f"does not match the post-remediation state ASR applied ({post_remediation_enabled}). "
            f"The resource was modified after the ASR remediation."
        )

    # No drift. Restore the pre-remediation state (skip the API call if already there).
    if is_currently_enabled == was_originally_enabled:
        return {
            "Message": f"Cluster {db_cluster_id} is already in its pre-remediation state. No rollback action needed.",
            "Status": "SUCCESS",
        }

    rds.modify_db_cluster(
        DBClusterIdentifier=db_cluster_id,
        DeletionProtection=was_originally_enabled,
        ApplyImmediately=apply_immediately,
    )
    logger.info(
        "Deletion protection restored (rollback)", extra={"dbClusterId": db_cluster_id}
    )
    return {
        "Message": f"Successfully restored deletion protection to {was_originally_enabled} for cluster {db_cluster_id}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
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
