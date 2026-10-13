# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""ElastiCache.1 — EnableElastiCacheBackups rollback script (shared rollback framework).

capture_and_remediate is fail-open (a snapshot failure never blocks remediation); execute_rollback
is fail-closed (any safety-gate failure aborts, raising RuntimeError so SSM reports ROLLBACK_FAILED).
State is the integer SnapshotRetentionLimit (0 = backups disabled). Like the forward remediation, the
setting is applied on the ElastiCache cluster or the replication group named by the resource ARN; the
same resource is read at capture and restored at rollback.
"""
from __future__ import annotations

import logging
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

CONTROL_ID = "ElastiCache.1"

_VALID_PARTITIONS = ("aws", "aws-cn", "aws-us-gov")
_INVALID_ARN_MESSAGE = "Missing or invalid required parameter: ResourceARN (expected an ElastiCache cluster or replication-group ARN)"

ResourceKind = Literal["cluster", "replicationgroup"]
_KIND_CLUSTER: ResourceKind = "cluster"
_KIND_REPLICATION_GROUP: ResourceKind = "replicationgroup"
_MODIFIABLE_KINDS = (_KIND_CLUSTER, _KIND_REPLICATION_GROUP)
# ElastiCache maps a missing resource to a different error code per resource type.
_NOT_FOUND_CODE = {
    _KIND_CLUSTER: "CacheClusterNotFound",
    _KIND_REPLICATION_GROUP: "ReplicationGroupNotFoundFault",
}


class ResourceTarget(TypedDict):
    kind: ResourceKind
    identifier: str


class ElastiCacheClient(Protocol):
    # Parameter names mirror the boto3 ElastiCache API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def describe_cache_clusters(
        self, *, CacheClusterId: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def describe_replication_groups(
        self, *, ReplicationGroupId: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    # modify_cache_cluster is always called with exactly these two args — type them so call sites are checked.
    def modify_cache_cluster(
        self, *, CacheClusterId: str, SnapshotRetentionLimit: int
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names

    # Called with exactly these args; SnapshottingClusterId only for a cluster-mode-disabled group.
    def modify_replication_group(
        self,
        *,
        ReplicationGroupId: str,
        SnapshotRetentionLimit: int,
        SnapshottingClusterId: str = ...,
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names


class CaptureAndRemediateEvent(TypedDict):
    ResourceARN: str
    AccountId: str
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str
    SnapshotRetentionPeriod: int


class ExecuteRollbackEvent(TypedDict):
    ResourceARN: str
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str


class ElastiCacheResponseError(RollbackError):
    """DescribeCacheClusters/DescribeReplicationGroups returned a response this control cannot use.

    Distinct from SnapshotValidationError so the SSM step output tells a malformed API response apart from
    a malformed snapshot, and from ValueError, which this module raises for bad event parameters.
    """


def _is_resource_kind(value: str) -> TypeGuard[ResourceKind]:
    return value in _MODIFIABLE_KINDS


def _validate_resource_arn(event: dict[str, object], account_id: str) -> ResourceTarget:
    """Validate the ElastiCache ARN, confirm its account matches account_id, and return (kind, identifier);
    raises ValueError on invalid input.

    ElastiCache ARNs are 7 colon-separated segments: arn:partition:elasticache:region:account:kind:id.
    """
    value = event.get("ResourceARN")
    if not isinstance(value, str):
        raise ValueError(_INVALID_ARN_MESSAGE)
    parts = value.split(":", 6)
    if len(parts) != 7 or parts[0] != "arn":
        raise ValueError(_INVALID_ARN_MESSAGE)
    partition, service, region, account, kind, identifier = parts[1:]
    is_valid_arn = (
        partition in _VALID_PARTITIONS
        and service == "elasticache"
        and bool(region)
        and account.isdigit()
        and len(account) == 12
        and bool(identifier)
    )
    if not is_valid_arn:
        raise ValueError(_INVALID_ARN_MESSAGE)
    if not _is_resource_kind(
        kind
    ):  # separate check so the TypeGuard narrows kind for the return
        raise ValueError(_INVALID_ARN_MESSAGE)
    if account != account_id:
        raise ValueError(
            f"ResourceARN account ({account}) does not match the executing account ({account_id}); "
            f"refusing to operate on a cross-account resource."
        )
    return ResourceTarget(kind=kind, identifier=identifier)


def _is_strict_int(value: object) -> TypeGuard[int]:
    # A real int, excluding bool (an int subclass).
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_retention(value: object) -> int:
    """Narrow the SnapshotRetentionPeriod target at the boundary. Must be a positive integer (backups on)."""
    if _is_strict_int(value):
        retention = value
    elif isinstance(value, str):
        try:
            retention = int(value)
        except ValueError as error:
            raise ValueError(
                f"Invalid SnapshotRetentionPeriod: {value!r} (expected a positive integer)"
            ) from error
    else:
        raise ValueError(
            f"Invalid SnapshotRetentionPeriod: {value!r} (expected a positive integer)"
        )
    if retention < 1:
        raise ValueError(
            f"Invalid SnapshotRetentionPeriod: {retention} (expected a positive integer to enable backups)"
        )
    return retention


def _optional_str(event: dict[str, object], name: str) -> str:
    # Guard fail-open capture fields: a non-string (e.g. None from SSM) becomes "" (skip snapshot), not "None".
    value = event.get(name)
    return value if isinstance(value, str) else ""


def _describe_one(client: ElastiCacheClient, target: ResourceTarget) -> dict[str, Any]:
    """Describe the single cluster or replication group, mapping the not-found code to ResourceNotFoundError."""
    kind, identifier = target["kind"], target["identifier"]
    try:
        if kind == _KIND_CLUSTER:
            items = client.describe_cache_clusters(CacheClusterId=identifier).get(
                "CacheClusters", []
            )
        else:
            items = client.describe_replication_groups(
                ReplicationGroupId=identifier
            ).get("ReplicationGroups", [])
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == _NOT_FOUND_CODE[kind]:
            raise ResourceNotFoundError(
                f"ElastiCache {kind} {identifier} not found."
            ) from error
        raise
    if not items:
        raise ResourceNotFoundError(f"ElastiCache {kind} {identifier} not found.")
    return items[0]


def _get_snapshot_retention(client: ElastiCacheClient, target: ResourceTarget) -> int:
    value = _describe_one(client, target).get("SnapshotRetentionLimit")
    if not _is_strict_int(value):
        kind, identifier = target["kind"], target["identifier"]
        raise ElastiCacheResponseError(
            f"ElastiCache {kind} {identifier} returned no integer SnapshotRetentionLimit ({value!r}); "
            "refusing to act on an unknown backup configuration."
        )
    return value


def _first_node_group_member(replication_group: dict[str, Any], identifier: str) -> str:
    """The first node group member's cache cluster id, used as SnapshottingClusterId for a cluster-mode-
    disabled replication group. Guards the nested API shape so a malformed response gives a clear error.
    """
    node_groups = replication_group.get("NodeGroups") or []
    members = node_groups[0].get("NodeGroupMembers") if node_groups else None
    if not members:
        raise ElastiCacheResponseError(
            f"Replication group {identifier} has no node group members; cannot determine SnapshottingClusterId."
        )
    cluster_id = members[0].get("CacheClusterId")
    if not cluster_id:
        raise ElastiCacheResponseError(
            f"Replication group {identifier}: first node group member has no CacheClusterId."
        )
    return cluster_id


def _set_snapshot_retention(
    client: ElastiCacheClient, target: ResourceTarget, *, retention: int
) -> None:
    """Set SnapshotRetentionLimit on the cluster or replication group. A cluster-mode-disabled replication
    group requires SnapshottingClusterId when enabling backups (retention > 0), mirroring the remediation.
    """
    kind, identifier = target["kind"], target["identifier"]
    if kind == _KIND_CLUSTER:
        client.modify_cache_cluster(
            CacheClusterId=identifier, SnapshotRetentionLimit=retention
        )
        return
    replication_group = _describe_one(client, target)
    if retention > 0 and replication_group.get("ClusterMode") == "disabled":
        client.modify_replication_group(
            ReplicationGroupId=identifier,
            SnapshotRetentionLimit=retention,
            SnapshottingClusterId=_first_node_group_member(
                replication_group, identifier
            ),
        )
        return
    client.modify_replication_group(
        ReplicationGroupId=identifier, SnapshotRetentionLimit=retention
    )


def _validate_retention_from_snapshot(
    snapshot_state: dict[str, Any],
    execution_id: str,
    which: Literal["preRemediationState", "postRemediationState"],
) -> int:
    value = snapshot_state.get("SnapshotRetentionLimit")
    if not _is_strict_int(value):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: missing integer '{which}.SnapshotRetentionLimit'."
        )
    return value


def _validate_capture_event(
    event: dict[str, object]
) -> tuple[CaptureAndRemediateEvent, ResourceTarget]:
    account_id = event.get("AccountId")
    if (
        not isinstance(account_id, str)
        or not account_id.isdigit()
        or len(account_id) != 12
    ):
        raise ValueError(
            "Missing or invalid required parameter: AccountId (expected 12-digit AWS account ID)"
        )
    target = _validate_resource_arn(event, account_id)
    validated = CaptureAndRemediateEvent(
        ResourceARN=str(event["ResourceARN"]),
        AccountId=account_id,
        RemediationConfigBucket=_optional_str(event, "RemediationConfigBucket"),
        AutomationExecutionId=_optional_str(event, "AutomationExecutionId"),
        SnapshotRetentionPeriod=_validate_retention(
            event.get("SnapshotRetentionPeriod")
        ),
    )
    return validated, target


def _validate_rollback_event(
    event: dict[str, object]
) -> tuple[ExecuteRollbackEvent, ResourceTarget]:
    # Common fields validated by the shared helper; only the resource ARN is control-specific.
    common = validate_common_rollback_fields(event)
    target = _validate_resource_arn(
        event, common["AccountId"]
    )  # validates the ARN + account match
    validated = ExecuteRollbackEvent(
        ResourceARN=str(event["ResourceARN"]),
        AccountId=common["AccountId"],
        RemediationConfigBucket=common["RemediationConfigBucket"],
        ExecutionId=common["ExecutionId"],
        SnapshotVersionId=common["SnapshotVersionId"],
    )
    return validated, target


def capture_and_remediate(event: dict[str, object], _context: object) -> CaptureResult:
    """Enable backups to at least the target retention. The S3 snapshot write is fail-open (never blocks
    remediation); the current-state read is required, so a transient read error fails rather than risk a
    silent downgrade under the minimum semantics."""
    validated, target = _validate_capture_event(event)
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]
    target_retention = validated["SnapshotRetentionPeriod"]

    client: ElastiCacheClient = boto3.client("elasticache", config=ROLLBACK_BOTO_CONFIG)
    # Read the current retention up front. This read is required (not fail-open): SnapshotRetentionPeriod is
    # a minimum, so without the current value we cannot tell whether setting the target would raise or shrink
    # an already-higher retention. A transient read error therefore fails the remediation (it is retried)
    # rather than blindly setting the target; a missing resource raises ResourceNotFoundError.
    current_retention = _get_snapshot_retention(client, target)

    # Already meets the minimum -> no-op; never downgrade a higher existing retention.
    if current_retention >= target_retention:
        logger.info(
            "SnapshotRetentionLimit already meets the target minimum; no remediation needed",
            extra={
                "target": target,
                "current": current_retention,
                "minimum": target_retention,
            },
        )
        return {
            "snapshotStored": "false",
            "snapshotVersionId": "",
            "rollbackDescription": f"No remediation needed: SnapshotRetentionLimit ({current_retention}) already meets the minimum ({target_retention}).",
        }

    # Snapshot the pre-remediation state before modifying. The S3 write is fail-open — a snapshot failure
    # never blocks the remediation (rollback is simply unavailable for this execution).
    is_snapshot_stored, snapshot_version_id = capture_snapshot(
        bucket,
        execution_id=execution_id,
        account_id=account_id,
        resource_id=validated["ResourceARN"],
        control_id=CONTROL_ID,
        pre_state={"SnapshotRetentionLimit": current_retention},
        # Intended post-state, written pre-remediation. Guarantees pre != post (so rollback can
        # distinguish drift); a failed remediation leaves an inert orphan snapshot that's never used.
        post_state={"SnapshotRetentionLimit": target_retention},
    )

    _set_snapshot_retention(client, target, retention=target_retention)
    logger.info(
        "Automatic backups enabled",
        extra={"target": target, "retention": target_retention},
    )

    # Rollback needs the version id as well as a stored snapshot: an unversioned bucket returns
    # (True, ""), and execute_rollback fails closed on an empty SnapshotVersionId. Reporting
    # snapshotStored="true" there would promise a rollback that cannot run.
    is_rollback_available = is_snapshot_stored and bool(snapshot_version_id)
    if not is_rollback_available:
        rollback_description = (
            "Rollback unavailable: pre-remediation state was not captured."
        )
    else:
        rollback_description = f"Restore SnapshotRetentionLimit to {current_retention} for ElastiCache {target['kind']} {target['identifier']}"
    return {
        "snapshotStored": "true" if is_rollback_available else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": rollback_description,
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    """Fail-closed rollback: reads the snapshot by its recorded version id (tamper-proof) and aborts
    on drift, so a state the operator set after remediation is never overwritten."""
    validated, target = _validate_rollback_event(event)
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

    # Verify the snapshot belongs to the resource being rolled back, guarding against an execution id
    # that resolves to a different resource's snapshot.
    snapshot_resource_id = snapshot.get("resourceId")
    if snapshot_resource_id != validated["ResourceARN"]:
        raise SnapshotValidationError(
            f"Rollback aborted for ElastiCache {target['kind']} {target['identifier']}: snapshot resourceId "
            f"({snapshot_resource_id!r}) does not match the target resource ARN ({validated['ResourceARN']!r})."
        )

    pre_state = get_pre_remediation_state(snapshot, execution_id)
    original_retention = _validate_retention_from_snapshot(
        pre_state, execution_id, "preRemediationState"
    )
    post_state = get_post_remediation_state(snapshot, execution_id)
    post_retention = _validate_retention_from_snapshot(
        post_state, execution_id, "postRemediationState"
    )

    client: ElastiCacheClient = boto3.client("elasticache", config=ROLLBACK_BOTO_CONFIG)
    current_retention = _get_snapshot_retention(client, target)

    action = resolve_rollback_action(
        current_retention, original_retention, post_retention
    )
    if action is RollbackAction.NOOP:
        return {
            "Message": f"ElastiCache {target['kind']} {target['identifier']} is already in its pre-remediation state. No rollback action needed.",
            "Status": "SUCCESS",
        }
    if action is RollbackAction.DRIFT:
        raise SnapshotValidationError(
            f"Rollback aborted for ElastiCache {target['kind']} {target['identifier']}: current SnapshotRetentionLimit "
            f"({current_retention}) does not match the post-remediation state ASR applied ({post_retention}). "
            f"The resource was modified after the ASR remediation."
        )

    _set_snapshot_retention(client, target, retention=original_retention)
    logger.info(
        "SnapshotRetentionLimit restored (rollback)",
        extra={"target": target, "retention": original_retention},
    )
    return {
        "Message": f"Successfully restored SnapshotRetentionLimit to {original_retention} for ElastiCache {target['kind']} {target['identifier']}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    return dispatch_rollback_handler(
        event, context, capture_fn=capture_and_remediate, rollback_fn=execute_rollback
    )
