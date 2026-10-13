# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""DynamoDB.6 — EnableDynamoDBDeletionProtection rollback script.

Handlers:
  capture_and_remediate: Captures the pre-remediation DeletionProtectionEnabled
      state to S3, then enables it. Fail-open: if snapshot write fails,
      remediation still proceeds.
  execute_rollback: Reads and validates the snapshot from S3, and if the table
      is still in the post-remediation state, restores the original setting.

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

CONTROL_ID = "DynamoDB.6"

# Standard-mode retries so transient DynamoDB throttling does not spuriously fail the step.
BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


class DynamoDBClient(Protocol):
    # Parameter names mirror the boto3 DynamoDB API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def describe_table(
        self, *, TableName: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def update_table(
        self, *, TableName: str, DeletionProtectionEnabled: bool
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names


class CaptureAndRemediateEvent(TypedDict):
    ResourceArn: str
    AccountId: str
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str


class ExecuteRollbackEvent(TypedDict):
    ResourceArn: str
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

    snapshotStored: str
    snapshotVersionId: str
    rollbackDescription: str
    Message: str
    Status: str


class TableNotFoundError(RollbackError):
    """The target DynamoDB table no longer exists."""


_TABLE_ARN_MARKER = ":table/"


def _validate_table_arn(event: dict[str, object]) -> str:
    """Validate ResourceArn is present and a DynamoDB table ARN (arn:...:table/NAME); return it."""
    resource_arn = event.get("ResourceArn")
    if (
        not isinstance(resource_arn, str)
        or not resource_arn.startswith("arn:")
        or _TABLE_ARN_MARKER not in resource_arn
        or not resource_arn.split(_TABLE_ARN_MARKER, 1)[1]
    ):
        raise ValueError(
            "Missing or invalid required parameter: ResourceArn (expected a DynamoDB table ARN)"
        )
    return resource_arn


def _table_name_from_arn(resource_arn: str) -> str:
    return resource_arn.split(_TABLE_ARN_MARKER, 1)[1]


def _get_deletion_protection(dynamodb: DynamoDBClient, table_name: str) -> bool:
    """Return the table's current DeletionProtectionEnabled, raising if the table is gone."""
    try:
        table = dynamodb.describe_table(TableName=table_name)["Table"]
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            raise TableNotFoundError(
                f"DynamoDB table {table_name} not found."
            ) from error
        raise
    return bool(table.get("DeletionProtectionEnabled", False))


def _read_pre_remediation_state(snapshot: dict[str, Any], execution_id: str) -> bool:
    """Return the snapshot's pre-remediation DeletionProtectionEnabled flag (envelope validated in common)."""
    pre_state = get_pre_remediation_state(snapshot, execution_id)
    enabled = pre_state.get("DeletionProtectionEnabled")
    if not isinstance(enabled, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'preRemediationState.DeletionProtectionEnabled'."
        )
    return enabled


def _read_post_remediation_state(snapshot: dict[str, Any], execution_id: str) -> bool:
    """Return the snapshot's post-remediation DeletionProtectionEnabled flag (envelope validated in common)."""
    post_state = get_post_remediation_state(snapshot, execution_id)
    enabled = post_state.get("DeletionProtectionEnabled")
    if not isinstance(enabled, bool):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing boolean 'postRemediationState.DeletionProtectionEnabled'."
        )
    return enabled


def _validate_capture_event(event: dict[str, object]) -> CaptureAndRemediateEvent:
    """Validate the SSM-supplied capture event at the module boundary and return a narrowed object."""
    resource_arn = _validate_table_arn(event)
    account_id = event.get("AccountId")
    if not isinstance(account_id, str) or not account_id:
        raise ValueError("Missing required parameter: AccountId")
    return CaptureAndRemediateEvent(
        ResourceArn=resource_arn,
        AccountId=account_id,
        RemediationConfigBucket=str(event.get("RemediationConfigBucket", "")),
        AutomationExecutionId=str(event.get("AutomationExecutionId", "")),
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    """Validate the SSM-supplied rollback event at the module boundary and return a narrowed object."""
    resource_arn = _validate_table_arn(event)
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
        ResourceArn=resource_arn,
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
    resource_arn: str,
    was_deletion_protection_enabled: bool,
) -> tuple[bool, str]:
    """Write the pre-remediation snapshot to S3 (fail-open). Returns (is_stored, versionId).

    Empty bucket/execution_id (a runbook started without the rollback parameters) skips the write.
    """
    if not bucket or not execution_id:
        logger.warning(
            "Snapshot skipped: missing bucket or execution ID",
            extra={"bucket": bucket, "executionId": execution_id},
        )
        return False, ""
    snapshot_data = build_snapshot(
        resource_arn,
        CONTROL_ID,
        {"DeletionProtectionEnabled": was_deletion_protection_enabled},
        {"DeletionProtectionEnabled": True},
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
    """Capture the pre-remediation DeletionProtectionEnabled state to S3 (fail-open), then enable it."""
    validated = _validate_capture_event(event)
    resource_arn = validated["ResourceArn"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]
    table_name = _table_name_from_arn(resource_arn)

    dynamodb: DynamoDBClient = boto3.client("dynamodb", config=BOTO_CONFIG)
    is_currently_enabled = _get_deletion_protection(dynamodb, table_name)

    # Snapshot-first (per design): capture the pre-remediation state to S3 BEFORE remediating.
    # If the enable below fails, the SSM step fails and the Orchestrator never marks the execution
    # rollbackAvailable (rollback is offered only for successful remediations), so an orphaned
    # snapshot is cleaned up by the S3 lifecycle rule and never used for a rollback/drift check.
    is_snapshot_stored, snapshot_version_id = _capture_snapshot(
        bucket,
        execution_id=execution_id,
        account_id=account_id,
        resource_arn=resource_arn,
        was_deletion_protection_enabled=is_currently_enabled,
    )

    if not is_currently_enabled:
        dynamodb.update_table(TableName=table_name, DeletionProtectionEnabled=True)
        logger.info("Deletion protection enabled", extra={"tableName": table_name})
    else:
        logger.info(
            "Deletion protection already enabled; no change needed",
            extra={"tableName": table_name},
        )

    rollback_description = (
        f"Disable deletion protection for DynamoDB table {table_name}"
        if not is_currently_enabled
        else f"Deletion protection was already enabled for DynamoDB table {table_name} (no-op rollback)"
    )
    return {
        "snapshotStored": "true" if is_snapshot_stored else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": rollback_description,
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    """
    1. Read and validate the snapshot from S3 (by its recorded version id, tamper-proof)
    2. Drift check: abort if the resource is no longer in the post-remediation state ASR applied
       (i.e. it was modified after remediation)
    3. Restore the original pre-remediation DeletionProtectionEnabled setting
    """
    validated = _validate_rollback_event(event)
    resource_arn = validated["ResourceArn"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["ExecutionId"]
    snapshot_version_id = validated["SnapshotVersionId"]
    table_name = _table_name_from_arn(resource_arn)

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

    dynamodb: DynamoDBClient = boto3.client("dynamodb", config=BOTO_CONFIG)
    is_currently_enabled = _get_deletion_protection(dynamodb, table_name)

    # Drift check: the resource must still be in the post-remediation state ASR applied. If it has
    # changed since remediation, someone modified it afterward — abort the rollback and surface the drift.
    if is_currently_enabled != post_remediation_enabled:
        raise SnapshotValidationError(
            f"Rollback aborted for table {table_name}: current deletion protection ({is_currently_enabled}) "
            f"does not match the post-remediation state ASR applied ({post_remediation_enabled}). "
            f"The resource was modified after the ASR remediation."
        )

    # No drift. Restore the pre-remediation state (skip the API call if already there).
    if is_currently_enabled == was_originally_enabled:
        return {
            "Message": f"Table {table_name} is already in its pre-remediation state. No rollback action needed.",
            "Status": "SUCCESS",
        }

    dynamodb.update_table(
        TableName=table_name, DeletionProtectionEnabled=was_originally_enabled
    )
    logger.info(
        "Deletion protection restored (rollback)", extra={"tableName": table_name}
    )
    return {
        "Message": f"Successfully restored deletion protection to {was_originally_enabled} for table {table_name}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    """Single inline entry point (one script per document): dispatch on the Rollback parameter.

    Returns a unified payload containing every declared SSM output key so the collapsed
    SnapshotRemediateOrRollback step's output selectors resolve on both the remediation and rollback paths.
    """
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
