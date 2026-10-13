# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""S3.6 — S3BlockDenylist (PutS3BucketPolicyDeny) rollback script (shared rollback framework).

The remediation appends a single explicit Deny statement (denying the sensitive/denylisted actions to
every cross-account AWS principal already named in the bucket policy) tagged with a stable Sid. Rollback
removes exactly that ASR statement — it does NOT wholesale-restore the pre-remediation policy, so any
legitimate edits the operator made to other statements after remediation are preserved.

capture_and_remediate is fail-open (a snapshot failure never blocks remediation); execute_rollback is
fail-closed (any safety-gate failure aborts, raising RollbackError so SSM reports ROLLBACK_FAILED).
State for the drift check is the ASR statement itself (present-and-unmodified vs absent vs modified),
keyed via resolve_rollback_action. The resource id is the bucket NAME (not an ARN).
"""
from __future__ import annotations

import json
import logging
import re
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
    read_snapshot,
    resolve_rollback_action,
    validate_common_rollback_fields,
)

# fmt: on
# %%INCLUDE=common/snapshot_utils.py%%

CONTROL_ID = "S3.6"
# Stable marker on the deny statement the remediation appends, so rollback can target exactly it.
ASR_SID = "ASR-S3.6-DenyCrossAccountAccess"
AwsPartition = Literal["aws", "aws-cn", "aws-us-gov"]
# A parsed JSON node. Recursive, so the nested members are quoted forward references (the SSM runtime is
# python3.11, which has no PEP 695 `type` statement).
JsonValue = str | int | float | bool | None | dict[str, "JsonValue"] | list["JsonValue"]
_VALID_PARTITIONS: tuple[AwsPartition, ...] = ("aws", "aws-cn", "aws-us-gov")
# S3 general-purpose bucket naming: 3-63 chars, lowercase letters/digits/dots/hyphens, start/end alphanumeric.
_BUCKET_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")


class S3Client(Protocol):
    # Parameter names mirror the boto3 S3 API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def get_bucket_policy(
        self, *, Bucket: str, ExpectedBucketOwner: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names

    def put_bucket_policy(
        self, *, Bucket: str, ExpectedBucketOwner: str, Policy: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names

    def delete_bucket_policy(
        self, *, Bucket: str, ExpectedBucketOwner: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names


class CaptureAndRemediateEvent(TypedDict):
    BucketName: str
    AccountId: str
    DenyList: list[str]
    Partition: AwsPartition
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str


class ExecuteRollbackEvent(TypedDict):
    BucketName: str
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str


class BucketNotFoundError(ResourceNotFoundError):
    """The target S3 bucket no longer exists."""


class RemediationError(RuntimeError):
    """The remediation could not be applied (e.g. no bucket policy to append the deny to, or verify failed)."""


# The bucket policy is a bucket subresource, so a read-back can lag the write; bound the re-reads.
_VERIFY_ATTEMPTS = 5
_VERIFY_DELAY_SECONDS = 2


class DriftDetectedError(RollbackError):
    """The live ASR statement no longer matches what the remediation wrote; the snapshot itself is fine.

    Defined here rather than in snapshot_utils: that module is %%INCLUDE-inlined into every rollback
    runbook, so shared additions cost template bytes 11x over. Promote it when a second control needs it.
    """


class RollbackValidationError(RollbackError, ValueError):
    """A rollback event field is missing or malformed.

    Subclasses RollbackError so every failure the rollback step can raise shares one family, and ValueError
    because a bad input value is what it is — callers and tests that treat validation failures as ValueError
    keep working. The capture path keeps raising plain ValueError, where a rollback-specific type would be a
    misnomer.
    """


def _validate_bucket_name(event: dict[str, object]) -> str:
    value = event.get("BucketName")
    # Length + S3 general-purpose bucket naming (lowercase letters/digits/dots/hyphens, 3-63 chars);
    # the SSM parameter already constrains this, so this is defense-in-depth for a direct caller.
    if not isinstance(value, str) or not _BUCKET_NAME_PATTERN.fullmatch(value):
        raise ValueError(
            "Missing or invalid required parameter: BucketName (expected an S3 bucket name)"
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


def _is_partition(value: object) -> TypeGuard[AwsPartition]:
    return value in _VALID_PARTITIONS


def _validate_partition(event: dict[str, object]) -> AwsPartition:
    partition = event.get("Partition")
    if not _is_partition(partition):
        raise ValueError(
            f"Missing or invalid required parameter: Partition (expected one of {list(_VALID_PARTITIONS)})"
        )
    return partition


def _validate_denylist(event: dict[str, object]) -> list[str]:
    # DenyList arrives from SSM as a comma-delimited string; normalize to a de-duplicated, ordered list of
    # non-empty action tokens so the deny statement (and its drift comparison) is deterministic.
    raw = event.get("DenyList")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(
            "Missing or invalid required parameter: DenyList (expected a comma-delimited action list)"
        )
    actions: list[str] = []
    for token in raw.split(","):
        action = token.strip()
        if action and action not in actions:
            actions.append(action)
    if not actions:
        raise ValueError(
            "Missing or invalid required parameter: DenyList (no actions after parsing)"
        )
    return actions


def _optional_str(event: dict[str, object], name: str) -> str:
    # Guard fail-open capture fields: a non-string (e.g. None from SSM) becomes "" (skip snapshot), not "None".
    value = event.get(name)
    return value if isinstance(value, str) else ""


def _get_bucket_policy(s3: S3Client, bucket: str, account_id: str) -> str | None:
    """Return the bucket's current policy JSON string, or None when the bucket has no policy.
    A missing bucket maps to BucketNotFoundError; other errors propagate."""
    try:
        return s3.get_bucket_policy(Bucket=bucket, ExpectedBucketOwner=account_id).get(
            "Policy"
        )
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code == "NoSuchBucketPolicy":
            return None
        if code in ("NoSuchBucket", "404"):
            raise BucketNotFoundError(f"S3 bucket {bucket} not found.") from error
        raise


def _parse_policy(policy_json: str | None) -> dict[str, Any] | None:
    if policy_json is None:
        return None
    parsed = json.loads(policy_json)
    if not isinstance(parsed, dict):
        raise ValueError("Bucket policy is not a JSON object")
    return parsed


def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    # IAM/S3 policy grammar allows Statement to be a single object or a list; normalize to a list so a
    # single-statement policy isn't dropped on capture or missed on rollback.
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    return statements if isinstance(statements, list) else []


def _find_asr_statement(policy: dict[str, Any] | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    for statement in _statements(policy):
        if isinstance(statement, dict) and statement.get("Sid") == ASR_SID:
            return statement
    return None


def _canonicalize(value: JsonValue) -> JsonValue:
    """Recursively sort dict keys and list elements, and unwrap single-element lists. S3 canonicalizes a
    single-element array into a scalar on read-back, so a stored ["x"] and the live "x" must compare equal;
    combined with sorting, this makes statement equality order- and representation-insensitive.
    """
    if isinstance(value, dict):
        return {k: _canonicalize(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        items = sorted(
            (_canonicalize(v) for v in value),
            key=lambda item: json.dumps(item, sort_keys=True),
        )
        return items[0] if len(items) == 1 else items
    return value


def _normalize(statement: JsonValue) -> str:
    # Canonical form for equality. Callers pass a policy statement or None, but the parameter is typed
    # JsonValue — the same type _canonicalize accepts — because that is what this function forwards, and
    # dict[str, Any] would let through values json.dumps cannot serialise. None normalizes to "", which is
    # the pre-remediation state key for a statement that is absent.
    if statement is None:
        return ""
    return json.dumps(_canonicalize(statement), sort_keys=True)


def _principal_account(principal: str) -> str:
    """The account a policy principal belongs to, or "" when it names no account.

    A principal is either a bare 12-digit account id or an ARN whose 5th colon-separated segment is the
    account. Anything else (notably the "*" wildcard) yields "" so the caller skips it. str.isdigit() is
    True for non-ASCII digits such as "１２３", hence the isascii() guard.
    """
    if principal.isascii() and principal.isdigit() and len(principal) == 12:
        return principal
    segments = principal.split(":")
    return segments[4] if len(segments) > 4 else ""


def _statement_cross_account_arns(statement: Any, bucket_account: str) -> list[str]:
    """The AWS principal ARNs named by a single statement that belong to a DIFFERENT account than the
    bucket owner. Statements that are not a dict, or carry a wildcard ('*') or non-AWS principal, name
    none."""
    if not isinstance(statement, dict):
        return []
    principal = statement.get("Principal")
    if not principal or principal == "*" or not isinstance(principal, dict):
        return []
    aws = principal.get("AWS")
    if aws is None:
        return []
    aws_list = aws if isinstance(aws, list) else [aws]
    return [
        arn
        for arn in aws_list
        if isinstance(arn, str)
        and (principal_account := _principal_account(arn))
        and principal_account != bucket_account
    ]


def _collect_cross_account_principals(
    policy: dict[str, Any], bucket_account: str
) -> list[str]:
    """Every distinct AWS principal ARN in the policy that belongs to a DIFFERENT account than the bucket
    owner (ordered, de-duplicated). Statements with a wildcard ('*') principal are skipped, mirroring the
    forward remediation."""
    principals: list[str] = []
    for statement in _statements(policy):
        for arn in _statement_cross_account_arns(statement, bucket_account):
            if arn not in principals:
                principals.append(arn)
    return principals


class DenyStatement(TypedDict):
    """The exact shape of the Deny statement ASR adds; narrower than the dict[str, Any] policy it joins."""

    Sid: str
    Effect: str
    Principal: dict[str, list[str]]
    Action: list[str]
    Resource: list[str]


def _build_deny_statement(
    *, principals: list[str], actions: list[str], bucket: str, partition: AwsPartition
) -> DenyStatement:
    return {
        "Sid": ASR_SID,
        "Effect": "Deny",
        "Principal": {"AWS": principals},
        "Action": actions,
        "Resource": [
            f"arn:{partition}:s3:::{bucket}",
            f"arn:{partition}:s3:::{bucket}/*",
        ],
    }


def _validate_capture_event(event: dict[str, object]) -> CaptureAndRemediateEvent:
    return CaptureAndRemediateEvent(
        BucketName=_validate_bucket_name(event),
        AccountId=_validate_account_id(event),
        DenyList=_validate_denylist(event),
        Partition=_validate_partition(event),
        RemediationConfigBucket=_optional_str(event, "RemediationConfigBucket"),
        AutomationExecutionId=_optional_str(event, "AutomationExecutionId"),
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    # Common fields (12-digit AccountId + fail-closed SnapshotVersionId) validated by the shared helper;
    # only the bucket name is control-specific. The shared helper and the local validators raise plain
    # ValueError (correct for the capture path), so re-type it here to keep every rollback failure a
    # RollbackError. A missing SnapshotVersionId already raises SnapshotValidationError and passes through.
    try:
        common = validate_common_rollback_fields(event)
        bucket = _validate_bucket_name(event)
    except ValueError as error:
        raise RollbackValidationError(str(error)) from error
    return ExecuteRollbackEvent(
        BucketName=bucket,
        AccountId=common["AccountId"],
        RemediationConfigBucket=common["RemediationConfigBucket"],
        ExecutionId=common["ExecutionId"],
        SnapshotVersionId=common["SnapshotVersionId"],
    )


def _verify_asr_statement(
    s3: S3Client, bucket: str, account_id: str, *, expect_present: bool
) -> bool:
    """Re-read the policy until it agrees with the write, or the attempts run out.

    Per the S3 data consistency model, strong read-after-write applies to "PUT and DELETE requests of
    objects" (plus object ACLs, tags and metadata), while "Bucket configurations have an eventual
    consistency model" — and the bucket policy is a bucket configuration. So a single read-back can
    legitimately still show the pre-write policy. Without the retry a remediation that did apply could be
    failed, which also discards the snapshot version id and with it the one-click rollback for the bucket.
    """
    for attempt in range(_VERIFY_ATTEMPTS):
        is_present = (
            _find_asr_statement(
                _parse_policy(_get_bucket_policy(s3, bucket, account_id))
            )
            is not None
        )
        if is_present == expect_present:
            return True
        if attempt < _VERIFY_ATTEMPTS - 1:
            time.sleep(_VERIFY_DELAY_SECONDS)
    return False


def _apply_and_verify(
    s3: S3Client,
    *,
    bucket: str,
    account_id: str,
    remediated_policy: dict[str, Any],
    principal_count: int,
    is_snapshot_stored: bool,
    snapshot_version_id: str,
) -> CaptureResult:
    """Persist the remediated policy, confirm the ASR deny statement stuck, and build the capture result."""
    s3.put_bucket_policy(
        Bucket=bucket,
        ExpectedBucketOwner=account_id,
        Policy=json.dumps(remediated_policy),
    )
    # Confirm the deny statement persisted before reporting success (retried: see _verify_asr_statement).
    if not _verify_asr_statement(s3, bucket, account_id, expect_present=True):
        raise RemediationError(
            f"Verification failed: the ASR deny statement is not present on bucket {bucket} after the update."
        )
    logger.info(
        "Cross-account deny statement added",
        extra={"bucket": bucket, "principals": principal_count},
    )

    is_rollback_available = is_snapshot_stored and bool(snapshot_version_id)
    rollback_description = (
        f"Remove the ASR cross-account deny statement ({ASR_SID}) from bucket {bucket}"
        if is_rollback_available
        else "Rollback unavailable: pre-remediation state was not captured."
    )
    return {
        "snapshotStored": "true" if is_rollback_available else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": rollback_description,
    }


def capture_and_remediate(event: dict[str, object], _context: object) -> CaptureResult:
    """Fail-open capture: a snapshot read/write failure never blocks the security remediation."""
    validated = _validate_capture_event(event)
    bucket = validated["BucketName"]
    account_id = validated["AccountId"]
    actions = validated["DenyList"]
    partition = validated["Partition"]
    config_bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]

    s3: S3Client = boto3.client("s3", config=ROLLBACK_BOTO_CONFIG)
    current_policy_json = _get_bucket_policy(s3, bucket, account_id)
    current_policy = _parse_policy(current_policy_json)

    # S3.6 remediation appends a Deny to an existing policy; without a policy there is no cross-account
    # grant to deny, so there is nothing to remediate.
    if current_policy is None:
        raise RemediationError(
            f"Bucket {bucket} has no bucket policy; nothing to restrict. Cannot apply the S3.6 remediation."
        )

    # No-op: the ASR deny statement is already present (e.g. a re-run). Skip the snapshot (a later rollback
    # would be a misleading no-op) and don't re-apply.
    if _find_asr_statement(current_policy) is not None:
        logger.info(
            "ASR deny statement already present; no remediation needed, snapshot skipped",
            extra={"bucket": bucket},
        )
        return {
            "snapshotStored": "false",
            "snapshotVersionId": "",
            "rollbackDescription": "No remediation needed: the ASR cross-account deny statement was already present.",
        }

    principals = _collect_cross_account_principals(current_policy, account_id)
    if not principals:
        raise RemediationError(
            f"Bucket {bucket} policy has no cross-account principals to deny; cannot build the S3.6 deny statement."
        )

    deny_statement = _build_deny_statement(
        principals=principals, actions=actions, bucket=bucket, partition=partition
    )
    remediated_policy = {
        **current_policy,
        "Statement": [*_statements(current_policy), deny_statement],
    }

    # Snapshot the pre-remediation policy + the exact statement ASR will add (used for the drift check on
    # rollback), before mutating. Fail-open: a snapshot failure must not block the remediation.
    is_snapshot_stored, snapshot_version_id = capture_snapshot(
        config_bucket,
        execution_id=execution_id,
        account_id=account_id,
        resource_id=bucket,
        control_id=CONTROL_ID,
        pre_state={"BucketPolicy": current_policy_json},
        post_state={"AsrStatement": deny_statement},
    )

    return _apply_and_verify(
        s3,
        bucket=bucket,
        account_id=account_id,
        remediated_policy=remediated_policy,
        principal_count=len(principals),
        is_snapshot_stored=is_snapshot_stored,
        snapshot_version_id=snapshot_version_id,
    )


def _asr_statement_from_snapshot(
    config_bucket: str,
    *,
    execution_id: str,
    account_id: str,
    bucket: str,
    snapshot_version_id: str,
) -> dict[str, Any]:
    """Read the snapshot by its recorded version id and return the exact statement ASR wrote.

    That statement is the drift baseline. Fail-closed: a missing, unreadable, mismatched or malformed
    snapshot raises rather than letting a rollback proceed on an unverified baseline.
    """
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
    if snapshot_resource_id != bucket:
        raise SnapshotValidationError(
            f"Rollback aborted for bucket {bucket}: snapshot resourceId ({snapshot_resource_id!r}) "
            f"does not match the target bucket ({bucket!r})."
        )

    # Only the post state is needed: rollback removes the ASR statement from the CURRENT policy.
    post_asr_statement = get_post_remediation_state(snapshot, execution_id).get(
        "AsrStatement"
    )
    if not isinstance(post_asr_statement, dict):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: missing 'postRemediationState.AsrStatement' object."
        )
    return post_asr_statement


def _remove_asr_statement(
    s3: S3Client, bucket: str, account_id: str, current_policy: dict[str, Any]
) -> None:
    """Persist the policy without the ASR statement, deleting the policy entirely if nothing else remains."""
    remaining = [
        statement
        for statement in _statements(current_policy)
        if not (isinstance(statement, dict) and statement.get("Sid") == ASR_SID)
    ]
    if remaining:
        s3.put_bucket_policy(
            Bucket=bucket,
            ExpectedBucketOwner=account_id,
            Policy=json.dumps({**current_policy, "Statement": remaining}),
        )
        return
    # Removing the ASR statement would leave a statement-less policy, which S3 rejects; the bucket had only
    # the ASR statement, so delete the policy entirely.
    s3.delete_bucket_policy(Bucket=bucket, ExpectedBucketOwner=account_id)


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    """Fail-closed rollback: reads the snapshot by its recorded version id (tamper-proof), aborts on drift,
    and removes only the ASR-tagged deny statement (preserving any other current statements).
    """
    validated = _validate_rollback_event(event)
    bucket = validated["BucketName"]
    account_id = validated["AccountId"]

    post_asr_statement = _asr_statement_from_snapshot(
        validated["RemediationConfigBucket"],
        execution_id=validated["ExecutionId"],
        account_id=account_id,
        bucket=bucket,
        snapshot_version_id=validated["SnapshotVersionId"],
    )

    s3: S3Client = boto3.client("s3", config=ROLLBACK_BOTO_CONFIG)
    current_policy = _parse_policy(_get_bucket_policy(s3, bucket, account_id))

    # Decide on the ASR statement itself: absent -> NOOP (already rolled back / never applied); present but
    # different from what ASR wrote -> DRIFT (operator edited it) -> abort; present and unmodified -> RESTORE.
    action = resolve_rollback_action(
        _normalize(_find_asr_statement(current_policy)),
        "",
        _normalize(post_asr_statement),
    )
    if action is RollbackAction.NOOP:
        return {
            "Message": f"Bucket {bucket} has no ASR deny statement to remove; already in its pre-remediation state.",
            "Status": "SUCCESS",
        }
    if action is RollbackAction.DRIFT:
        raise DriftDetectedError(
            f"Rollback aborted for bucket {bucket}: the ASR deny statement ({ASR_SID}) was modified after the "
            f"ASR remediation. Refusing to remove an operator-modified statement."
        )

    # RESTORE implies the ASR statement was found in a policy, so current_policy is not None. Guard
    # explicitly rather than assert: asserts are stripped under `python -O`, so the guard would vanish.
    if current_policy is None:  # pragma: no cover - unreachable for a RESTORE action
        raise RollbackError(
            f"Rollback aborted for bucket {bucket}: the bucket policy was removed during rollback."
        )
    _remove_asr_statement(s3, bucket, account_id, current_policy)

    # Confirm the ASR statement is gone before reporting success (retried: see _verify_asr_statement).
    if not _verify_asr_statement(s3, bucket, account_id, expect_present=False):
        raise RollbackError(
            f"Rollback verification failed: the ASR deny statement is still present on bucket {bucket}."
        )
    logger.info("ASR deny statement removed (rollback)", extra={"bucket": bucket})
    return {
        "Message": f"Successfully removed the ASR cross-account deny statement from bucket {bucket}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    return dispatch_rollback_handler(
        event, context, capture_fn=capture_and_remediate, rollback_fn=execute_rollback
    )
