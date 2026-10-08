# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""SNS.1 — EnableEncryptionForSNSTopic rollback script (shared rollback framework).

capture_and_remediate is fail-open (a snapshot failure never blocks remediation); execute_rollback
is fail-closed (any safety-gate failure aborts). Rollback failures raise RuntimeError so SSM
Automation marks the step Failed, which the orchestrator reports as ROLLBACK_FAILED.

State is the topic's KmsMasterKeyId (a string). An unencrypted topic has no key; that is normalized
to "" throughout, and faithful restore of an originally-unencrypted topic clears the key ("").
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

CONTROL_ID = "SNS.1"

_VALID_PARTITIONS = ("aws", "aws-cn", "aws-us-gov")


def _parse_arn(value: object) -> tuple[str, list[str]] | None:
    """Return (arn, segments) if value is a structurally valid ARN, else None.

    ARN layout: arn:partition:service:region:account:resource. Enforces exactly 6 segments,
    the literal 'arn' prefix, and a known partition — so a lookalike string (e.g. another
    service's resource name containing ':sns:') cannot pass a substring check. Returning the
    validated str (narrowed from object) lets callers return it without a type: ignore cast.
    """
    if not isinstance(value, str):
        return None
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[1] not in _VALID_PARTITIONS:
        return None
    return value, parts


class SNSClient(Protocol):
    # Parameter names mirror the boto3 SNS API (PascalCase kwargs), so S117 (snake_case) does not apply.
    def get_topic_attributes(
        self, *, TopicArn: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter name

    def set_topic_attributes(
        self, *, TopicArn: str, AttributeName: str, AttributeValue: str
    ) -> dict[str, Any]: ...  # NOSONAR boto3 API parameter names


class CaptureAndRemediateEvent(TypedDict):
    TopicArn: str
    KmsKeyArn: str
    AccountId: str
    # Always present post-validation; empty string skips snapshot capture (fail-open), remediation still runs.
    RemediationConfigBucket: str
    AutomationExecutionId: str


class ExecuteRollbackEvent(TypedDict):
    TopicArn: str
    AccountId: str
    RemediationConfigBucket: str
    ExecutionId: str
    SnapshotVersionId: str


def _validate_topic_arn(event: dict[str, object], account_id: str) -> str:
    """Structurally validate the SNS TopicArn and confirm it belongs to the executing account.

    Full 6-segment ARN parse (not a substring check): service must be 'sns', account must be 12
    digits, and the resource (topic name) non-empty. Also enforces that the ARN's account equals
    account_id (the executing account the remediation runs under) — defense-in-depth so the
    remediation never operates on a topic in a different account than the credential owner.
    """
    parsed = _parse_arn(event.get("TopicArn"))
    if parsed is None:
        raise ValueError(
            "Missing or invalid required parameter: TopicArn (expected an SNS topic ARN)"
        )
    topic_arn, parts = parsed
    if (
        parts[2] != "sns"
        or not parts[3]
        or not parts[4].isdigit()
        or len(parts[4]) != 12
        or not parts[5]
    ):
        raise ValueError(
            "Missing or invalid required parameter: TopicArn (expected an SNS topic ARN)"
        )
    if parts[4] != account_id:
        raise ValueError(
            f"TopicArn account ({parts[4]}) does not match the executing account ({account_id}); "
            f"refusing to operate on a cross-account topic."
        )
    return topic_arn


def _validate_kms_key_arn(value: object) -> str:
    """Structurally validate the KMS key ARN used as the SNS KmsMasterKeyId.

    Requires a well-formed KMS ARN (service 'kms') whose resource is a key/ or alias/ — so an
    unvalidated or malformed identifier cannot be set as the topic's encryption key.
    """
    parsed = _parse_arn(value)
    if parsed is None:
        raise ValueError(
            "Missing or invalid required parameter: KmsKeyArn (expected a KMS key ARN)"
        )
    kms_key_arn, parts = parsed
    if (
        parts[2] != "kms"
        or not parts[3]
        or not parts[4].isdigit()
        or len(parts[4]) != 12
        or not parts[5].startswith(("key/", "alias/"))
    ):
        raise ValueError(
            "Missing or invalid required parameter: KmsKeyArn (expected a KMS key ARN)"
        )
    return kms_key_arn


def _get_kms_key(sns: SNSClient, topic_arn: str) -> str:
    # Absent or empty KmsMasterKeyId both mean "unencrypted"; normalize to "". A deleted topic maps to
    # ResourceNotFoundError (a classified RollbackError) so the rollback path surfaces it per the module
    # contract instead of leaking a raw botocore exception; the capture path handles it fail-open.
    try:
        attrs = sns.get_topic_attributes(TopicArn=topic_arn).get("Attributes", {})
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in (
            "NotFound",
            "NotFoundException",
        ):
            raise ResourceNotFoundError(f"SNS topic {topic_arn} not found.") from error
        raise
    key = attrs.get("KmsMasterKeyId", "")
    return key if isinstance(key, str) else ""


def _read_pre_state(sns: SNSClient, topic_arn: str) -> tuple[str, bool]:
    """Read pre-remediation KmsMasterKeyId (fail-open). Returns (key, can_capture_snapshot);
    on read error returns ("", False) so the snapshot is skipped but remediation still proceeds.
    The first value is meaningless unless the second is True."""
    try:
        return _get_kms_key(sns, topic_arn), True
    except (ClientError, BotoCoreError, ResourceNotFoundError):
        logger.exception(
            "Pre-remediation state read failed (fail-open); skipping snapshot",
            extra={"topicArn": topic_arn},
        )
        return "", False


def _validate_pre_kms_key(snapshot: dict[str, Any], execution_id: str) -> str:
    """Assert the field is a string so a malformed snapshot fails closed (not coerced). "" = was unencrypted."""
    pre_state = get_pre_remediation_state(snapshot, execution_id)
    key = pre_state.get("KmsMasterKeyId")
    if not isinstance(key, str):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing string 'preRemediationState.KmsMasterKeyId'."
        )
    return key


def _validate_post_kms_key(snapshot: dict[str, Any], execution_id: str) -> str:
    """Post-state counterpart of _validate_pre_kms_key; baseline for the drift check."""
    post_state = get_post_remediation_state(snapshot, execution_id)
    key = post_state.get("KmsMasterKeyId")
    if not isinstance(key, str):
        raise SnapshotValidationError(
            f"Snapshot for execution {execution_id} is malformed: "
            f"missing string 'postRemediationState.KmsMasterKeyId'."
        )
    return key


def _optional_str(event: dict[str, object], name: str) -> str:
    """Return the value only if it is a real string, else "". Guards the fail-open capture fields so a
    non-string (e.g. None from SSM) becomes "" (skip snapshot) rather than str(None) == "None".
    """
    value = event.get(name)
    return value if isinstance(value, str) else ""


def _validate_capture_event(event: dict[str, object]) -> CaptureAndRemediateEvent:
    """Validate the SSM-supplied capture event at the module boundary and return a narrowed object."""
    account_id = event.get("AccountId")
    if (
        not isinstance(account_id, str)
        or not account_id.isdigit()
        or len(account_id) != 12
    ):
        raise ValueError(
            "Missing or invalid required parameter: AccountId (expected 12-digit AWS account ID)"
        )
    topic_arn = _validate_topic_arn(event, account_id)
    kms_key_arn = _validate_kms_key_arn(event.get("KmsKeyArn"))
    return CaptureAndRemediateEvent(
        TopicArn=topic_arn,
        KmsKeyArn=kms_key_arn,
        AccountId=account_id,
        RemediationConfigBucket=_optional_str(event, "RemediationConfigBucket"),
        AutomationExecutionId=_optional_str(event, "AutomationExecutionId"),
    )


def _validate_rollback_event(event: dict[str, object]) -> ExecuteRollbackEvent:
    # Common fields validated by the shared helper; only the topic ARN is control-specific.
    common = validate_common_rollback_fields(event)
    topic_arn = _validate_topic_arn(event, common["AccountId"])
    return ExecuteRollbackEvent(
        TopicArn=topic_arn,
        AccountId=common["AccountId"],
        RemediationConfigBucket=common["RemediationConfigBucket"],
        ExecutionId=common["ExecutionId"],
        SnapshotVersionId=common["SnapshotVersionId"],
    )


def _verify_key_applied(
    sns: SNSClient, topic_arn: str, expected_key: str, *, error_cls: type[RuntimeError]
) -> None:
    """Re-read KmsMasterKeyId and confirm it equals expected_key, else raise error_cls. A silently
    ineffective set — accepted-but-not-applied, wrong key, or eventual consistency — must fail rather
    than report success. Used symmetrically: the remediation path expects the CMK, the rollback path
    expects the restored original key ("" = unencrypted)."""
    applied_key = _get_kms_key(sns, topic_arn)
    if applied_key != expected_key:
        raise error_cls(
            f"SNS topic {topic_arn} KmsMasterKeyId is {applied_key!r} after set, expected {expected_key!r}."
        )


def _build_rollback_description(
    topic_arn: str, original_key: str, is_rollback_available: bool
) -> str:
    """Human-readable rollback description for the finding. When no usable snapshot exists, state that
    rollback is unavailable rather than promising a restore that would fail closed."""
    if not is_rollback_available:
        return "Rollback unavailable: pre-remediation state was not captured."
    if not original_key:
        return f"Restore SNS topic {topic_arn} to unencrypted (clear KmsMasterKeyId)"
    return f"Restore SNS topic {topic_arn} KmsMasterKeyId to {original_key}"


def capture_and_remediate(event: dict[str, object], _context: object) -> CaptureResult:
    """Capture handler. Fail-open: a snapshot read/write failure must never block the security
    remediation, so capture is best-effort and set_topic_attributes always runs."""
    validated = _validate_capture_event(event)
    topic_arn = validated["TopicArn"]
    remediation_key = validated["KmsKeyArn"]
    account_id = validated["AccountId"]
    bucket = validated["RemediationConfigBucket"]
    execution_id = validated["AutomationExecutionId"]

    sns: SNSClient = boto3.client("sns", config=ROLLBACK_BOTO_CONFIG)

    original_key, can_capture_snapshot = _read_pre_state(sns, topic_arn)

    # No-op remediation: the topic is already encrypted with the exact key we would apply (pre == post).
    # Gated on can_capture_snapshot: only trust original_key when the pre-state read actually succeeded
    # (on a fail-open read error it is "" and meaningless, so fall through to the normal remediate path).
    # The topic is already in the desired state, so no SetTopicAttributes call is needed; skip the snapshot
    # too (so a later rollback of this finding isn't a misleading no-op) and don't offer rollback.
    if can_capture_snapshot and original_key == remediation_key:
        logger.info(
            "Topic already encrypted with the remediation key; no remediation needed, snapshot skipped",
            extra={"topicArn": topic_arn},
        )
        return {
            "snapshotStored": "false",
            "snapshotVersionId": "",
            "rollbackDescription": "No remediation needed: topic already encrypted with the target key.",
        }

    is_snapshot_stored, snapshot_version_id = (
        capture_snapshot(
            bucket,
            execution_id=execution_id,
            account_id=account_id,
            resource_id=topic_arn,
            control_id=CONTROL_ID,
            pre_state={"KmsMasterKeyId": original_key},
            # Intended post-state = the CMK the remediation applies (captured, not re-resolved at
            # rollback); a failed remediation leaves an inert orphan snapshot that's never used.
            post_state={"KmsMasterKeyId": remediation_key},
        )
        if can_capture_snapshot
        else (False, "")
    )

    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="KmsMasterKeyId",
        AttributeValue=remediation_key,
    )
    logger.info("SNS topic encryption enabled", extra={"topicArn": topic_arn})
    _verify_key_applied(sns, topic_arn, remediation_key, error_cls=RuntimeError)

    # A snapshot is only rollback-able if it has a version id: execute_rollback reads the exact captured
    # version (validate_common_rollback_fields fails closed on an empty version id). write_snapshot returns
    # no version id when the bucket has versioning disabled, so a stored-but-unversioned snapshot can never
    # be rolled back — report it as not stored rather than promise a restore that will always fail closed.
    is_rollback_available = is_snapshot_stored and bool(snapshot_version_id)
    return {
        "snapshotStored": "true" if is_rollback_available else "false",
        "snapshotVersionId": snapshot_version_id,
        "rollbackDescription": _build_rollback_description(
            topic_arn, original_key, is_rollback_available
        ),
    }


def execute_rollback(event: dict[str, object], _context: object) -> RollbackResult:
    """Rollback handler. Fail-closed: reads the snapshot by its recorded version id (tamper-proof)
    and aborts on any drift, so a state the operator set after remediation is never overwritten.
    """
    validated = _validate_rollback_event(event)
    topic_arn = validated["TopicArn"]
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
        # Corrupt / non-JSON snapshot content is a validation problem, not an I/O read failure.
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

    original_key = _validate_pre_kms_key(snapshot, execution_id)
    post_key = _validate_post_kms_key(snapshot, execution_id)

    sns: SNSClient = boto3.client("sns", config=ROLLBACK_BOTO_CONFIG)
    # Fail-closed: a deleted topic surfaces as ResourceNotFoundError (from _get_kms_key); any other read
    # failure is wrapped as SnapshotReadError so every rollback failure is a classified RollbackError.
    try:
        current_key = _get_kms_key(sns, topic_arn)
    except (ClientError, BotoCoreError) as error:
        raise SnapshotReadError(
            f"Failed to read current state for topic {topic_arn}: {error}"
        ) from error

    action = resolve_rollback_action(current_key, original_key, post_key)
    if action is RollbackAction.NOOP:
        return {
            "Message": f"Topic {topic_arn} is already in its pre-remediation state. No rollback action needed.",
            "Status": "SUCCESS",
        }
    if action is RollbackAction.DRIFT:
        raise SnapshotValidationError(
            f"Rollback aborted for topic {topic_arn}: current KmsMasterKeyId ({current_key!r}) "
            f"does not match the post-remediation state ASR applied ({post_key!r}). "
            f"The resource was modified after the ASR remediation."
        )

    # Faithful restore to the captured original. original_key == "" clears encryption (back to unencrypted);
    # a non-empty original restores that exact key. Same SetTopicAttributes call either way.
    # Fail-closed: guard the TOCTOU window between the current-state read and this write. If the topic is
    # deleted mid-rollback (or the write otherwise fails), surface a classified RollbackError rather than a
    # raw botocore exception, per the module contract.
    try:
        sns.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="KmsMasterKeyId",
            AttributeValue=original_key,
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in (
            "NotFound",
            "NotFoundException",
        ):
            raise ResourceNotFoundError(
                f"SNS topic {topic_arn} not found during rollback restore."
            ) from error
        raise RollbackError(
            f"Failed to restore KmsMasterKeyId for topic {topic_arn}: {error}"
        ) from error
    except BotoCoreError as error:
        raise RollbackError(
            f"Failed to restore KmsMasterKeyId for topic {topic_arn}: {error}"
        ) from error
    # Fail-closed symmetry with the remediation path: verify the restore actually took effect (a silently
    # ineffective set must not report a successful rollback). Restore target is original_key ("" = unencrypted).
    _verify_key_applied(sns, topic_arn, original_key, error_cls=RollbackError)
    logger.info(
        "SNS topic encryption restored (rollback)", extra={"topicArn": topic_arn}
    )
    return {
        "Message": f"Successfully restored KmsMasterKeyId to {original_key!r} for topic {topic_arn}",
        "Status": "SUCCESS",
    }


def handler(event: dict[str, object], context: object) -> HandlerResult:
    return dispatch_rollback_handler(
        event, context, capture_fn=capture_and_remediate, rollback_fn=execute_rollback
    )
