# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Custom resource provider for migrating v2 EventBridge auto-remediation state to v3/v4 DynamoDB.

During upgrade from v2.x to v3.x/v4.x, this Lambda reads the ENABLED state of
per-control EventBridge rules (v2 mechanism) and writes them as enabled controls
in the DynamoDB RemediationConfigTable (v3+ mechanism). This preserves the
customer's auto-remediation settings across the upgrade.

v2 rule format (see v2.x source/lib/ssmplaybook.ts Trigger construct):

    {securityStandard}_{securityStandardVersion}_{controlId}_AutoTrigger

Example v2 rule names per supported standard:

    SC_2.0.0_S3.5_AutoTrigger
    AFSBP_1.0.0_S3.5_AutoTrigger
    NIST80053R5_5.0.0_CloudTrail.1_AutoTrigger
    PCI_3.2.1_PCI.S3.5_AutoTrigger
    CIS_1.2.0_1.5_AutoTrigger
    CIS_1.4.0_2.1.2_AutoTrigger
    CIS_3.0.0_2.1.1_AutoTrigger

v3+ uses Security Control IDs (e.g. S3.5, IAM.18) as the DynamoDB key. Each
standard's v2 control IDs map to Security Control IDs as follows:

* SC, AFSBP, NIST80053R5  -> control ID is already a Security Control ID
* PCI                     -> strip the leading "PCI." prefix
* CIS (1.2.0/1.4.0/3.0.0) -> look up in the per-version mapping below

The CIS lookup tables follow ASR's own v2 playbook routing (the SSM document
each CIS rule executed in v2 indicates its corresponding v3+ Security Control).
This is occasionally narrower than AWS's published CIS->SC mapping, since v2
collapsed some controls (e.g. all CIS v1.2.0 password-policy rules used a
single ASR-SetIAMPasswordPolicy document, which corresponds to SC IAM.7).

Controls that have no v3+ equivalent (e.g. CIS v1.2.0 4.2 in some standards)
are skipped: the DynamoDB UpdateItem uses ConditionExpression="attribute_exists"
so unknown control IDs fail the conditional check and do not interfere with
already-migrated entries.

Failure notification:

If `MIGRATION_NOTIFICATION_TOPIC_ARN` is set on the Lambda environment, this
provider publishes an SNS message when migration partially fails (one or more
controls couldn't be written) or fully fails (uncaught exception). The CDK
stack points this at the existing ASR status topic (`SO0111-ASR_Topic`) so
that operators get the notification through the same subscriptions they
already maintain for routine ASR status messages — avoiding a fresh
PendingConfirmation race during the v2 -> v3/v4 stack update.

This Lambda is designed to be removed in a future version once all customers
have upgraded past v2.
"""

from __future__ import annotations

from os import getenv
from typing import TYPE_CHECKING, Any, Literal, TypedDict

import boto3
import cfnresponse
from aws_lambda_powertools.utilities.data_classes import (
    CloudFormationCustomResourceEvent,
    event_source,
)
from aws_lambda_powertools.utilities.typing import LambdaContext
from botocore.config import Config
from botocore.exceptions import ClientError
from layer.powertools_logger import get_logger
from layer.tracer_utils import init_tracer

if TYPE_CHECKING:
    from mypy_boto3_sns.client import SNSClient

LOG_LEVEL = getenv("POWERTOOLS_LOG_LEVEL", "info")
logger = get_logger("migration_auto_remediation_provider", LOG_LEVEL)
tracer = init_tracer()

BOTO_CONFIG = Config(retries={"mode": "standard"}, connect_timeout=5, read_timeout=10)

# Initialized lazily via _get_sns_client() and cached for reuse across warm
# invocations. See the rationale on the getter below.
_sns_client: SNSClient | None = None


def _get_sns_client() -> SNSClient:
    global _sns_client
    if _sns_client is None:
        # Cached in the module-global _sns_client and reused across warm
        # invocations (same effect as initializing outside the handler).
        # Lazy creation is deliberate so the client binds after test mocking
        # (moto) or runtime credentials are in place, matching
        # get_securityhub_client in action_target_provider.py.
        # (Sonar S6243 is suppressed for this file in sonar-project.properties.)
        _sns_client = boto3.client("sns", config=BOTO_CONFIG)
    return _sns_client


# Suffix every v2 auto-remediation rule has.
V2_RULE_SUFFIX = "_AutoTrigger"

# v2 standard short names whose control IDs already match v3+ Security Control IDs.
SECURITY_CONTROL_ID_STANDARDS: frozenset[str] = frozenset(
    ("SC", "AFSBP", "NIST80053R5")
)

# v2 PCI rules use control IDs prefixed with "PCI." (e.g., PCI.S3.5).
PCI_STANDARD = "PCI"

# v2 CIS rules share a single "CIS" standard short name; the version distinguishes
# which mapping table to use.
CIS_STANDARD = "CIS"

# CIS-version-specific control ID -> v3+ Security Control ID lookup tables.
#
# These mirror the SSM document each CIS playbook routes to in v2 (one source
# of truth: source/playbooks/CIS{120,140,300}/ssmdocs/). Where v2 ASR did not
# ship a remediation for a given CIS control, no entry exists; UpdateItem then
# fails the attribute_exists check and the control is skipped during migration.
# Security Control IDs referenced by more than one CIS-version mapping below.
# Named once so the same literal isn't repeated across the three lookup tables.
_SC_IAM_18 = "IAM.18"
_SC_IAM_8 = "IAM.8"
_SC_IAM_3 = "IAM.3"
_SC_IAM_7 = "IAM.7"
_SC_CLOUDTRAIL_1 = "CloudTrail.1"
_SC_CLOUDTRAIL_2 = "CloudTrail.2"
_SC_CLOUDTRAIL_4 = "CloudTrail.4"
_SC_CLOUDTRAIL_7 = "CloudTrail.7"
_SC_CONFIG_1 = "Config.1"
_SC_KMS_4 = "KMS.4"
_SC_EC2_6 = "EC2.6"
_SC_EC2_2 = "EC2.2"

CIS120_TO_SECURITY_CONTROL_ID: dict[str, str] = {
    "1.20": _SC_IAM_18,
    "1.3": _SC_IAM_8,
    "1.4": _SC_IAM_3,
    "1.5": _SC_IAM_7,
    "2.1": _SC_CLOUDTRAIL_1,
    "2.2": _SC_CLOUDTRAIL_4,
    "2.3": "CloudTrail.6",
    "2.4": "CloudTrail.5",
    "2.5": _SC_CONFIG_1,
    "2.6": _SC_CLOUDTRAIL_7,
    "2.7": _SC_CLOUDTRAIL_2,
    "2.8": _SC_KMS_4,
    "2.9": _SC_EC2_6,
    "3.1": "CloudWatch.1",
    "4.1": "EC2.13",
    "4.3": _SC_EC2_2,
}

CIS140_TO_SECURITY_CONTROL_ID: dict[str, str] = {
    "1.12": _SC_IAM_8,
    "1.14": _SC_IAM_3,
    "1.17": _SC_IAM_18,
    "1.8": _SC_IAM_7,
    "2.1.1": "S3.4",
    "2.1.2": "S3.5",
    "2.1.5.1": "S3.1",
    "2.1.5.2": "S3.2",
    "2.2.1": "EC2.7",
    "3.1": _SC_CLOUDTRAIL_1,
    "3.2": _SC_CLOUDTRAIL_4,
    "3.3": "CloudTrail.6",
    "3.4": "CloudTrail.5",
    "3.5": _SC_CONFIG_1,
    "3.6": _SC_CLOUDTRAIL_7,
    "3.7": _SC_CLOUDTRAIL_2,
    "3.8": _SC_KMS_4,
    "3.9": _SC_EC2_6,
    "4.1": "CloudWatch.1",
    "5.3": _SC_EC2_2,
}

CIS300_TO_SECURITY_CONTROL_ID: dict[str, str] = {
    "1.12": _SC_IAM_8,
    "1.14": _SC_IAM_3,
    "1.17": _SC_IAM_18,
    "1.8": _SC_IAM_7,
    "2.1.1": "S3.5",
    "2.1.4.1": "S3.1",
    "2.1.4.2": "S3.2",
    "2.2.1": "EC2.7",
    "2.3.2": "RDS.13",
    "2.3.3": "RDS.2",
    "3.1": _SC_CLOUDTRAIL_1,
    "3.2": _SC_CLOUDTRAIL_4,
    "3.3": _SC_CONFIG_1,
    "3.4": _SC_CLOUDTRAIL_7,
    "3.5": _SC_CLOUDTRAIL_2,
    "3.6": _SC_KMS_4,
    "3.7": _SC_EC2_6,
    "5.4": _SC_EC2_2,
    "5.6": "EC2.8",
}

CIS_LOOKUP_BY_VERSION: dict[str, dict[str, str]] = {
    "1.2.0": CIS120_TO_SECURITY_CONTROL_ID,
    "1.4.0": CIS140_TO_SECURITY_CONTROL_ID,
    "3.0.0": CIS300_TO_SECURITY_CONTROL_ID,
}

# Legacy v2 control IDs that v3+ Security Hub renamed. These apply after
# standard translation, so they catch the AFSBP pass-through and PCI prefix-strip
# paths uniformly. Add new entries when v3+ adopts a control ID that v2 used a
# different name for.
LEGACY_CONTROL_ID_ALIASES: dict[str, str] = {
    # AFSBP and PCI v2 used "ELBv2.1"; v3+ ships this as "ELB.1".
    "ELBv2.1": "ELB.1",
}

# All v2 standard short-name prefixes the discovery scan should consider, each
# terminated with "_" so the EventBridge ListRules filter matches only that
# standard's rules.
V2_STANDARD_PREFIXES: tuple[str, ...] = (
    "SC_",
    "AFSBP_",
    "NIST80053R5_",
    "PCI_",
    "CIS_",
)

# Optional SNS topic ARN. When set, the Lambda publishes a notification on
# partial or full migration failure. When unset, the Lambda still completes
# successfully and only writes to logs (used for fresh installs or customers
# who haven't enabled the WebUI / AdminUserEmail).
NOTIFICATION_TOPIC_ARN_ENV = "MIGRATION_NOTIFICATION_TOPIC_ARN"


def _translate_to_security_control_id(
    standard: str, version: str, raw_control_id: str
) -> str | None:
    """Translate a v2 standard-specific control ID to a v3+ Security Control ID.

    Returns None if the standard/version is unknown or the CIS control has no
    ASR remediation in v2.
    """
    translated: str | None
    if standard in SECURITY_CONTROL_ID_STANDARDS:
        translated = raw_control_id
    elif standard == PCI_STANDARD:
        # PCI v2 control IDs are prefixed with "PCI." (e.g. PCI.S3.5 -> S3.5).
        if raw_control_id.startswith("PCI."):
            translated = raw_control_id[len("PCI.") :]
        else:
            # Defensive: if the prefix is missing for some reason, fall back to
            # the raw ID. This keeps a malformed rule visible in the logs rather
            # than silently dropped.
            translated = raw_control_id
    elif standard == CIS_STANDARD:
        cis_table = CIS_LOOKUP_BY_VERSION.get(version)
        if cis_table is None:
            return None
        translated = cis_table.get(raw_control_id)
        if translated is None:
            return None
    else:
        return None

    # Apply legacy-name aliasing last so it catches every translation path.
    return LEGACY_CONTROL_ID_ALIASES.get(translated, translated)


def extract_control_id_from_rule_name(rule_name: str) -> str | None:
    """Extract the v3+ Security Control ID from a v2 EventBridge rule name.

    v2 rule format: {Standard}_{Version}_{ControlId}_AutoTrigger
    Returns the translated Security Control ID (e.g. "S3.5", "IAM.18"), or
    None if the rule isn't a v2 auto-trigger rule or the control has no
    v3+ equivalent.
    """
    if not rule_name.endswith(V2_RULE_SUFFIX):
        return None

    # Strip the _AutoTrigger suffix
    without_suffix = rule_name[: -len(V2_RULE_SUFFIX)]

    # Split by underscore: [Standard, Version, ControlId...]
    # Control IDs can contain dots but not underscores, so the segments after
    # Standard_Version_ are the (possibly dotted) control ID.
    parts = without_suffix.split("_")
    if len(parts) < 3:
        return None

    standard, version = parts[0], parts[1]
    raw_control_id = "_".join(parts[2:])
    if not raw_control_id:
        return None

    return _translate_to_security_control_id(standard, version, raw_control_id)


def _control_id_for_enabled_rule(rule: dict[str, Any]) -> str | None:
    """Return the v3+ Security Control ID for an ENABLED v2 auto-trigger rule.

    Returns None (without logging) for rules that aren't ENABLED v2 auto-trigger
    rules. For a recognized auto-trigger rule that has no v3+ mapping, logs the
    skip and returns None so operators can trace it.
    """
    rule_name = rule["Name"]

    # Only process ENABLED rules with the v2 AutoTrigger suffix.
    if not rule_name.endswith(V2_RULE_SUFFIX) or rule.get("State") != "ENABLED":
        return None

    control_id = extract_control_id_from_rule_name(rule_name)
    if control_id is None:
        # Recognized v2 auto-trigger rule but no v3+ mapping (unknown standard or
        # unmapped CIS control). Logged so operators can trace which rules were
        # intentionally skipped during migration.
        logger.info(
            "Skipping rule with no v3+ mapping",
            extra={"rule_name": rule_name},
        )
    return control_id


def discover_enabled_v2_rules() -> list[str]:
    """List all v2 EventBridge rules that are ENABLED and extract their control IDs.

    Scans rules for every supported v2 standard prefix and translates each
    matched control ID to a v3+ Security Control ID. Returns a deduplicated
    list (e.g., ["S3.5", "EC2.2", "CloudTrail.1"]).
    """
    events_client = boto3.client("events", config=BOTO_CONFIG)
    enabled_controls: list[str] = []
    seen_controls: set[str] = set()

    for prefix in V2_STANDARD_PREFIXES:
        paginator = events_client.get_paginator("list_rules")
        for page in paginator.paginate(NamePrefix=prefix):
            for rule in page.get("Rules", []):
                control_id = _control_id_for_enabled_rule(rule)
                if control_id is None or control_id in seen_controls:
                    continue
                seen_controls.add(control_id)
                enabled_controls.append(control_id)
                logger.info(
                    "Found enabled v2 rule",
                    extra={"rule_name": rule["Name"], "control_id": control_id},
                )

    return enabled_controls


class MigrationResult(TypedDict):
    """Outcome of write_enabled_controls_to_table."""

    written: int
    failed_controls: list[str]


def write_enabled_controls_to_table(
    table_name: str, control_ids: list[str]
) -> MigrationResult:
    """Update controls in the DynamoDB config table to enabled.

    Uses update_item to set automatedRemediationEnabled=true for controls
    that were enabled in v2. This runs AFTER remediation_config_provider has
    populated the table with all controls as disabled, so we're updating
    existing items (not creating new ones).

    Returns the count of successfully updated controls and the list of control
    IDs that failed to update due to a non-recoverable per-item error (caller
    can use this list for operator notifications).
    """
    if not control_ids:
        return MigrationResult(written=0, failed_controls=[])

    dynamodb = boto3.resource(
        "dynamodb", region_name=getenv("AWS_REGION"), config=BOTO_CONFIG
    )
    table = dynamodb.Table(table_name)
    updated = 0
    failed_controls: list[str] = []

    for control_id in control_ids:
        try:
            table.update_item(
                Key={"controlId": control_id},
                UpdateExpression="SET automatedRemediationEnabled = :val, modifiedBy = :by",
                ExpressionAttributeValues={
                    ":val": True,
                    ":by": "v2-migration",
                },
                ConditionExpression="attribute_exists(controlId)",
            )
            updated += 1
        except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
            # Control doesn't exist in table (not a supported control in v3+) — skip
            logger.info(
                "Control not found in config table, skipping",
                extra={"control_id": control_id},
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDeniedException", "ResourceNotFoundException"):
                raise  # Non-recoverable — abort migration
            logger.error(
                "Failed to update control in table",
                extra={"control_id": control_id, "error": str(e)},
            )
            failed_controls.append(control_id)

    if failed_controls:
        logger.warning(
            "Migration completed with failures",
            extra={"failure_count": len(failed_controls)},
        )

    return MigrationResult(written=updated, failed_controls=failed_controls)


def notify_migration_failure(
    *,
    failed_controls: list[str],
    summary: str,
    topic_arn: str | None = None,
) -> bool:
    """Publish an operator-facing migration failure summary to SNS.

    Returns True if a notification was published, False if the topic is not
    configured (e.g. fresh install without WebUI / AdminUserEmail).

    Notifications are best-effort: a publish error is logged but never raised,
    so a misconfigured topic doesn't fail the stack update on top of an
    already-degraded migration.
    """
    arn = topic_arn if topic_arn is not None else getenv(NOTIFICATION_TOPIC_ARN_ENV)
    if not arn:
        logger.info(
            "Skipping migration failure notification — no SNS topic configured",
        )
        return False

    if failed_controls:
        body_lines = [
            "[ASR v2 -> v3/v4 migration]",
            "",
            summary,
            "",
            "The following controls were not migrated and need to be enabled "
            "manually in the ASR Web UI:",
            "",
        ]
        body_lines.extend(f"  - {c}" for c in sorted(failed_controls))
    else:
        body_lines = [
            "[ASR v2 -> v3/v4 migration]",
            "",
            summary,
        ]

    body = "\n".join(body_lines)
    subject = (
        "ASR auto-remediation migration: failures during upgrade"
        if failed_controls
        else "ASR auto-remediation migration: aborted during upgrade"
    )

    try:
        _get_sns_client().publish(TopicArn=arn, Subject=subject, Message=body)
        logger.info(
            "Published migration failure notification",
            extra={"failure_count": len(failed_controls)},
        )
        return True
    except ClientError as exc:
        logger.error(
            "Failed to publish migration failure notification",
            extra={"error": str(exc), "topic_arn": arn},
        )
        return False


RequestType = Literal["Create", "Update", "Delete"]


class MigrationEvent(TypedDict):
    request_type: RequestType
    table_name: str


def validate_event(event: CloudFormationCustomResourceEvent) -> MigrationEvent:
    """Validate CloudFormation event and return a narrowly typed object."""
    request_type = event["RequestType"]
    if request_type not in ("Create", "Update", "Delete"):
        raise ValueError(f"Unknown RequestType: {request_type}")
    table_name = event["ResourceProperties"].get("TableName", "")
    if not table_name or not isinstance(table_name, str):
        raise ValueError(
            "ResourceProperties.TableName is required and must be a non-empty string"
        )
    return MigrationEvent(request_type=request_type, table_name=table_name)


# aws_lambda_powertools decorators lack typed stubs
@event_source(data_class=CloudFormationCustomResourceEvent)  # type: ignore[untyped-decorator]
@tracer.capture_lambda_handler  # type: ignore[untyped-decorator]
def lambda_handler(
    event: CloudFormationCustomResourceEvent, context: LambdaContext
) -> None:
    """Migrate v2 auto-remediation settings to v3/v4 DynamoDB config table.

    Only runs on Create (first deployment of v3/v4). Update and Delete are no-ops.
    """
    response_data: dict[str, str] = {}

    try:
        validated = validate_event(event)

        if validated["request_type"] == "Create":
            logger.info("Checking for v2 EventBridge auto-remediation rules to migrate")
            enabled_controls = discover_enabled_v2_rules()

            if enabled_controls:
                logger.info(
                    f"Found {len(enabled_controls)} enabled v2 controls to migrate: "
                    f"{sorted(enabled_controls)}"
                )
                result = write_enabled_controls_to_table(
                    validated["table_name"], enabled_controls
                )
                logger.info(
                    f"Migration complete: {result['written']} controls written to DynamoDB"
                )
                response_data["MigratedControls"] = str(result["written"])

                if result["failed_controls"]:
                    notify_migration_failure(
                        failed_controls=result["failed_controls"],
                        summary=(
                            f"ASR migrated {result['written']} of "
                            f"{len(enabled_controls)} v2 auto-remediation controls. "
                            f"{len(result['failed_controls'])} control(s) failed."
                        ),
                    )
            else:
                logger.info(
                    "No enabled v2 EventBridge rules found. "
                    "This is expected for fresh installs or v3+ upgrades."
                )
                response_data["MigratedControls"] = "0"

        elif validated["request_type"] == "Update":
            logger.info("Update: No migration needed (already migrated on Create)")

        elif validated["request_type"] == "Delete":
            logger.info("Delete: No cleanup needed")

        cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)

    except Exception as exc:
        logger.exception(f"Migration failed: {exc}")
        # Don't fail the stack update — migration is best-effort.
        # Customer can still manually enable controls if migration fails.
        response_data["Error"] = str(exc)
        notify_migration_failure(
            failed_controls=[],
            summary=(
                "ASR auto-remediation migration aborted before any controls were "
                f"written. Reason: {exc}. Re-enable controls manually in the ASR "
                "Web UI."
            ),
        )
        cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)
