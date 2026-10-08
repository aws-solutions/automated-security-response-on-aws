# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""ElastiCache.2 — EnableElastiCacheVersionUpgrades rollback script.

Handlers:
  capture_and_remediate: Captures the pre-remediation AutoMinorVersionUpgrade
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

CONTROL_ID = "ElastiCache.2"

# Standard-mode retries so transient ElastiCache throttling does not spuriously fail the step.
BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


class ElastiCacheClient(Protocol):
    # Parameter names mirror the boto3 ElastiCache API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def describe_cache_clusters(
        self, *, CacheClusterId: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def modify_cache_cluster(
        self, *, CacheClusterId: str, AutoMinorVersionUpgrade: bool
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names


class CaptureAndRemediateEvent(TypedDict):
    ClusterId: str
    AccountId: str
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str


class ExecuteRollbackEvent(TypedDict):
    ClusterId: str
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
    """Unified dispatch payload: every declared SSM output key is always present so the collapsed
    SnapshotRemediateOrRollback step's output selectors resolve on both the remediation and rollback paths.
    """

    snapshotStored: Literal["true", "false", ""]
    snapshotVersionId: str
    rollbackDescription: str
    Message: str
    Status: Literal["SUCCESS", ""]


class ClusterNotFoundError(RollbackError):
    """The target ElastiCache cluster no longer exists."""


def _validate_cluster_id(event: dict[str, object]) -> str:
    cluster_id = event.get("ClusterId")
    if not isinstance(cluster_id, str) or not cluster_id:
        raise ValueError("Missing or invalid required parameter: ClusterId")
    return cluster_id


def _get_auto_minor_version_upgrade(
    elasticache: ElastiCacheClient, cluster_id: str
) -> bool:
    try:
        clusters = elasticache.describe_cache_clusters(CacheClusterId=cluster_id).get(
            "CacheClusters", []
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "CacheClusterNotFound":
            raise ClusterNotFoundError(
                f"ElastiCache cluster {cluster_id} not found."
            ) from error
        raise
    if not clusters:
        raise ClusterNotFoundError(f"ElastiCache cluster {cluster_id} not found.")
    return bool(clusters[0].get("AutoMinorVersionUpgrade", False))


def _read_pre_remediation_state(snapshot: dict[str, Any], execution_id: str) -> bool:
    pre_state = get_pre_remediation_state(snapshot, execution_id)
    is_enabled = pre_state.get("AutoMinorVersionUpgrade")
    if not isinstance(is_enabled, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'preRemediationState.AutoMinorVersionUpgrade'."
        )
    return is_enabled


def _read_post_remediation_state(snapshot: dict[str, Any], execution_id: str) -> bool:
    post_state = get_post_remediation_state(snapshot, execution_id)
    is_enabled = post_state.get("AutoMinorVersionUpgrade")
    if not isinstance(is_enabled, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'postRemediationState.AutoMinorVersionUpgrade'."
        )
    return is_enabled


def _validate_capture_event(event: dict[str, object]) -> CaptureAndRemediateEvent:
    cluster_id = _validate_cluster_id(event)
    account_id = event.get("AccountId")
    if not isinstance(account_id, str) or not account_id:
        raise ValueError("Missing required parameter: AccountId")
    return CaptureAndRemediateEvent(
        ClusterId=cluster_id,
        AccountId=account_id,
        RemediationConfigBucket=str(event.get("RemediationConfigBucket", "")),
        AutomationExecutionId=str(event.get("AutomationExecutionId", "")),
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    cluster_id = _validate_cluster_id(event)
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
        ClusterId=cluster_id,
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
    cluster_id: str,
    was_auto_upgrade_enabled: bool,
) -> tuple[bool, str]:
    if not bucket or not execution_id:
        logger.warning(
            "Snapshot skipped: missing bucket or execution ID",
            extra={"bucket": bucket, "executionId": execution_id},
        )
        return False, ""
    # postRemediationState is the state ASR *applies* (enabled), not a re-read; the drift check
    # compares the cluster's current AutoMinorVersionUpgrade against it before restoring.
    snapshot_data = build_snapshot(
        cluster_id,
        CONTROL_ID,
        {"AutoMinorVersionUpgrade": was_auto_upgrade_enabled},
        {"AutoMinorVersionUpgrade": True},
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
    cluster_id = validated["ClusterId"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]

    elasticache: ElastiCacheClient = boto3.client("elasticache", config=BOTO_CONFIG)
    is_currently_enabled = _get_auto_minor_version_upgrade(elasticache, cluster_id)

    # Snapshot-first (per design): capture the pre-remediation state to S3 BEFORE remediating.
    # If the enable below fails, the SSM step fails and the Orchestrator never marks the execution
    # rollbackAvailable (rollback is offered only for successful remediations), so an orphaned
    # snapshot is cleaned up by the S3 lifecycle rule and never used for a rollback/drift check.
    is_snapshot_stored, snapshot_version_id = _capture_snapshot(
        bucket,
        execution_id=execution_id,
        account_id=account_id,
        cluster_id=cluster_id,
        was_auto_upgrade_enabled=is_currently_enabled,
    )

    if not is_currently_enabled:
        elasticache.modify_cache_cluster(
            CacheClusterId=cluster_id, AutoMinorVersionUpgrade=True
        )
        logger.info(
            "Automatic minor version upgrades enabled", extra={"clusterId": cluster_id}
        )
    else:
        logger.info(
            "Automatic minor version upgrades already enabled; no change needed",
            extra={"clusterId": cluster_id},
        )

    rollback_description = (
        f"Disable automatic minor version upgrades for ElastiCache cluster {cluster_id}"
        if not is_currently_enabled
        else f"Automatic minor version upgrades were already enabled for ElastiCache cluster {cluster_id} (no-op rollback)"
    )
    return {
        "snapshotStored": "true" if is_snapshot_stored else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": rollback_description,
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    validated = _validate_rollback_event(event)
    cluster_id = validated["ClusterId"]
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

    was_originally_enabled = _read_pre_remediation_state(snapshot, execution_id)
    post_remediation_enabled = _read_post_remediation_state(snapshot, execution_id)

    elasticache: ElastiCacheClient = boto3.client("elasticache", config=BOTO_CONFIG)
    is_currently_enabled = _get_auto_minor_version_upgrade(elasticache, cluster_id)

    # Drift check: the resource must still be in the post-remediation state ASR applied. If it has
    # changed since remediation, someone modified it afterward — abort the rollback and surface the drift.
    if is_currently_enabled != post_remediation_enabled:
        raise SnapshotValidationError(
            f"Rollback aborted for cluster {cluster_id}: current automatic minor version upgrade "
            f"({is_currently_enabled}) does not match the post-remediation state ASR applied "
            f"({post_remediation_enabled}). The resource was modified after the ASR remediation."
        )

    # No drift. Restore the pre-remediation state (skip the API call if already there).
    if is_currently_enabled == was_originally_enabled:
        return {
            "Message": f"Cluster {cluster_id} is already in its pre-remediation state. No rollback action needed.",
            "Status": "SUCCESS",
        }

    elasticache.modify_cache_cluster(
        CacheClusterId=cluster_id, AutoMinorVersionUpgrade=was_originally_enabled
    )
    logger.info(
        "Automatic minor version upgrades restored (rollback)",
        extra={"clusterId": cluster_id},
    )
    return {
        "Message": f"Successfully restored automatic minor version upgrades to {was_originally_enabled} for cluster {cluster_id}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    # Validate the dispatch parameter at the entry point (system boundary). SSM's allowedValues
    # already constrains it, so this is defense-in-depth against a misconfigured direct caller.
    rollback_flag = event.get("Rollback", "")
    if not isinstance(rollback_flag, str) or rollback_flag not in ("", "ROLLBACK"):
        raise ValueError(
            f"Invalid Rollback parameter: {rollback_flag!r} (expected '' or 'ROLLBACK')."
        )
    if rollback_flag == "ROLLBACK":
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
