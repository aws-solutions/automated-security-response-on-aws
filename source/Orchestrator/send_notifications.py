# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import gzip
import json
import os
import re
from datetime import datetime, timezone
from typing import (
    TYPE_CHECKING,
    Any,
    Literal,
    Optional,
    Protocol,
    TypedDict,
    Union,
    cast,
)

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from layer import sechub_findings
from layer.asr_actions import CUSTOM_ACTION_NAME_ROLLBACK
from layer.awsapi_cached_client import AWSCachedClient
from layer.cloudwatch_metrics import CloudWatchMetrics
from layer.event_transformers import (
    Event,
    Notification,
    extract_account_id,
    extract_region,
    extract_resources,
    extract_severity,
    extract_stepfunctions_execution_id,
    extract_triggered_by,
    is_notified_workflow,
    is_resolved_item,
    resolve_finding_account_id,
    transform_stepfunctions_failure_event,
)
from layer.findings_repository import get_metric_attributes
from layer.history_repository import RemediationUpdateRequest
from layer.metrics import Metrics, is_ai_generated_remediation
from layer.powertools_logger import get_logger
from layer.remediation_data_service import (
    get_security_hub_console_url,
    map_remediation_status,
    update_remediation_status_and_history,
)
from layer.sechub_findings import (
    FindingInfo,
    extract_finding_id,
    extract_finding_info,
    extract_resource_id,
    extract_security_control_id,
    get_finding_type,
)
from layer.tracer_utils import init_tracer
from layer.utils import get_account_alias

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import Table

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")  # MUST BE SET in global variables
AWS_PARTITION = os.getenv("AWS_PARTITION", "aws")  # MUST BE SET in global variables

logger = get_logger("send_notifications")
tracer = init_tracer()

NOTIFICATION_QUEUE_URL = os.getenv("NOTIFICATION_QUEUE_URL")
# Explicit timeouts bound the SQS call so a hung endpoint cannot stall the Lambda
# for its full timeout; standard retries add headroom.
_BOTO_CONFIG = Config(retries={"mode": "standard"}, connect_timeout=5, read_timeout=10)
_sqs_client = boto3.client("sqs", config=_BOTO_CONFIG)


class _SecurityHubBatchUpdater(Protocol):
    """The subset of the Security Hub client this module uses."""

    def batch_update_findings(self, **kwargs: Any) -> dict[str, Any]: ...


# Created lazily via _get_sechub_client(): only the rollback path calls Security Hub, so
# cold starts that never run a rollback don't pay to construct this client.
_sechub_client: "_SecurityHubBatchUpdater | None" = None


def _first_element(value: list[Any] | str | None) -> str | None:
    """Extract the first element from an SSM output value (array-wrapped) or return as-is if string."""
    if value is None:
        return None
    if isinstance(value, list):
        first = value[0] if value else None
        return first if isinstance(first, str) else None
    return value if isinstance(value, str) else None


def _get_output_field(
    output: dict[str, Any], field: str, step_prefix: str = "SnapshotRemediateOrRollback"
) -> str | None:
    """Extract a field from remediation output, checking both flat and step-prefixed formats."""
    flat = _first_element(output.get(field))
    if flat is not None:
        return flat
    return _first_element(output.get(f"{step_prefix}.{field}"))


_rollback_config_table: "Table | None" = None


_dynamodb_resource = boto3.resource("dynamodb", config=_BOTO_CONFIG)


def _get_rollback_config_table() -> "Table | None":
    global _rollback_config_table
    if _rollback_config_table is None:
        table_name = os.environ.get("REMEDIATION_CONFIG_TABLE_NAME")
        if table_name:
            _rollback_config_table = _dynamodb_resource.Table(table_name)
    return _rollback_config_table


def _get_sechub_client() -> _SecurityHubBatchUpdater:
    global _sechub_client
    if _sechub_client is None:
        _sechub_client = boto3.client("securityhub", config=_BOTO_CONFIG)
    return _sechub_client


def _is_control_rollback_enabled(control_id: str) -> bool:
    """Check the Remediation Config Table for per-control rollback toggle.

    Returns True (rollback allowed) when:
      - The table name env var is not set (backward compat — no table, no gate)
      - The control's item has rollbackEnabled=true or the field is absent (default true)
    Returns False when rollbackEnabled is explicitly set to false.
    """
    table = _get_rollback_config_table()
    if not table:
        return True
    try:
        response = table.get_item(
            Key={"controlId": control_id}, ProjectionExpression="rollbackEnabled"
        )
        item = response.get("Item")
        if not item:
            return True
        return item.get("rollbackEnabled", True) is not False
    except Exception as e:
        logger.warning(
            "Failed to check rollbackEnabled, defaulting to enabled",
            extra={"controlId": control_id, "error": str(e)},
        )
        return True


def _set_if_present(target: dict[str, str], key: str, value: str | None) -> None:
    if value is not None:
        target[key] = value


def _enrich_notification_with_finding_info(
    notification_event: dict[str, str],
    finding_info: FindingInfo | None,
    finding_id: str,
    notification_block: Notification,
) -> None:
    if finding_info is not None:
        _set_if_present(
            notification_event, "standardName", finding_info.get("standard_name")
        )
        _set_if_present(
            notification_event, "standardVersion", finding_info.get("standard_version")
        )
        # Use a distinct key so it does not shadow the remediation "description"
        # that _publish_notification_event sets from notification_block["Message"].
        _set_if_present(
            notification_event,
            "findingDescription",
            finding_info.get("finding_description"),
        )
        finding_arn = finding_info.get("finding_arn")
        if finding_arn:
            _set_if_present(
                notification_event,
                "findingLink",
                get_security_hub_console_url(finding_arn),
            )

    if "findingLink" not in notification_event and finding_id:
        _set_if_present(
            notification_event, "findingLink", get_security_hub_console_url(finding_id)
        )

    _set_if_present(
        notification_event,
        "remediationOutput",
        notification_block.get("RemediationOutput"),
    )
    _set_if_present(
        notification_event,
        "stepFunctionsExecutionId",
        notification_block.get("StepFunctionsExecutionId"),
    )

    finding_account = finding_info.get("account") if finding_info is not None else None
    account_id_for_alias = finding_account or notification_event.get("accountId", "")
    if account_id_for_alias:
        try:
            _set_if_present(
                notification_event,
                "accountAlias",
                get_account_alias(account_id_for_alias),
            )
        except (ClientError, BotoCoreError) as alias_err:
            logger.warning(
                "Failed to fetch accountAlias, continuing without it",
                extra={"accountId": account_id_for_alias, "error": str(alias_err)},
            )


def _publish_notification_event(
    event: Event, status_from_event: str, *, finding_info: FindingInfo | None = None
) -> None:
    if not NOTIFICATION_QUEUE_URL:
        logger.warning(
            "NOTIFICATION_QUEUE_URL not configured; skipping new notification path"
        )
        return

    try:
        event_dict: dict[str, Any] = dict(event)
        finding_id = extract_finding_id(event_dict)
        control_id = extract_security_control_id(event_dict)
        resources = extract_resources(event)
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        notification_block = event.get("Notification", {})

        # Orchestrator-level failures (e.g. ASSUME_ROLE_FAILURE) can fire before
        # a finding is fully loaded, leaving Severity.Label empty. Empty severity
        # would be silently dropped by any explicit severityFilter on a channel
        # config. Fall back to "Critical" for non-success states so operators
        # filtering on severity still receive these high-signal failures.
        severity = extract_severity(event) or ""
        if not severity and status_from_event.upper() not in (
            "SUCCESS",
            "QUEUED",
            "ROLLBACK_SUCCESS",
        ):
            severity = "CRITICAL"

        notification_event: dict[str, str] = {
            "eventType": "remediation",
            "eventId": finding_id,
            "controlId": control_id or "",
            "accountId": extract_account_id(event),
            "region": extract_region(event),
            "severity": severity,
            "resourceType": resources.get("Type", ""),
            "resourceId": extract_resource_id(event_dict, resources),
            "title": f"{control_id or 'Unknown'} {status_from_event.lower()} in {extract_account_id(event)}",
            "description": notification_block.get("Message", ""),
            "remediationStatus": status_from_event,
            "remediationMessage": notification_block.get("Message")
            or notification_block.get("Details", ""),
            "detectedAt": now,
            "timestamp": now,
        }

        _enrich_notification_with_finding_info(
            notification_event, finding_info, finding_id, notification_block
        )

        _sqs_client.send_message(
            QueueUrl=NOTIFICATION_QUEUE_URL,
            MessageBody=json.dumps(notification_event),
        )
    except Exception as e:
        logger.warning("Failed to publish notification event", extra={"error": str(e)})


_EXCEPTION_LINE = re.compile(
    r"^(?:[\w.]+\.)?(\w*(?:Error|Exception|Exit)): (.+)$", re.MULTILINE
)
_TRACEBACK_FRAME = re.compile(r'File "[^"]*", line (\d+), in (\S+)')
_CAUSE_PREFIX = "Cause: "


def _messages_from_cause(cause: object) -> list[str]:
    """The messages inside a Lambda error cause, or its text when it carries none."""
    if not isinstance(cause, dict):
        return [str(cause)]

    lines: list[str] = []
    trace = cause.get("trace")
    if isinstance(trace, list):
        lines.extend(str(line) for line in trace)
    message = str(cause.get("errorMessage") or "")
    if message:
        lines.append(message)

    if lines:
        return lines
    return [str(cause)]


def _messages_from(raw_message: object) -> list[str]:
    """The individual messages behind the field, whatever shape it arrived in."""
    if isinstance(raw_message, str) and raw_message.startswith(_CAUSE_PREFIX):
        body = raw_message[len(_CAUSE_PREFIX) :]
        try:
            return _messages_from_cause(json.loads(body))
        except ValueError:
            return [body]

    parsed: object = raw_message
    if isinstance(raw_message, str):
        try:
            parsed = json.loads(raw_message)
        except ValueError:
            parsed = raw_message
    if isinstance(parsed, list):
        return [str(part) for part in parsed]
    return [str(parsed)]


def extract_failure_reason(raw_message: object) -> str:
    """The exception the script raised, else where it broke, else the messages themselves."""
    if not raw_message:
        return ""
    parts = _messages_from(raw_message)

    for part in reversed(parts):
        exceptions = _EXCEPTION_LINE.findall(part)
        if exceptions:
            name, detail = exceptions[-1]
            return f"{name}: {detail.strip()}"

    frames = [frame for part in parts for frame in _TRACEBACK_FRAME.findall(part)]
    if frames:
        line_number, function = frames[0]
        return (
            f"Failed in {function} at line {line_number}. The error message was "
            "truncated; see the Systems Manager automation execution for the full trace."
        )
    return " ".join(" ".join(part.split()) for part in parts)


def format_failure_message(
    raw_message: str, control_runbook_execution_id: Optional[str] = None
) -> str:
    """
    Clean up SSM automation failure messages for human-readable display.

    Removes SSM standard prefixes/suffixes and replaces newlines with spaces
    to create a single-line error message suitable for email notifications.

    Args:
        raw_message: The raw failure message from either the Remediation Runbook (if available) or Control Runbook
        execution_id: Optional SSM automation execution ID for debugging reference
    """
    if not raw_message:
        return ""

    # Remove SSM standard prefix and suffix - these are not useful for debugging in the context of ASR
    prefix = "Step fails when it is Poll action status for completion."
    suffix = "Please refer to Automation Service Troubleshooting Guide for more diagnosis details."

    cleaned_message = raw_message.removeprefix(prefix).removesuffix(suffix).strip()
    cleaned_message = " ".join(cleaned_message.split())

    debugging_tip = "Check the Systems Manager > Automation console in the member account for more details."
    if control_runbook_execution_id:
        debugging_tip += (
            f" The Automation Execution Id is {control_runbook_execution_id}"
        )

    return f"{cleaned_message} ({debugging_tip})"


def format_remediation_output(
    raw_output: str,
    control_runbook_execution_id: Optional[str] = None,
    control_runbook_status: Optional[str] = None,
) -> Union[dict[str, Any], str]:
    """
    Format remediation output for human-readable display in notifications.

    Handles two main formats:
    1. Success: Nested JSON like {"StepName.Output": ["{\"Message\":\"...\",\"Status\":\"...\"}"]}
       - Decodes the nested JSON and returns as a dict to avoid double-encoding in the notification
    2. Failure: Error messages with tracebacks and exception details - returns as formatted string

    Args:
        raw_output: The raw output from either the Remediation Runbook (if available) or Control Runbook
        execution_id: Optional SSM automation execution ID for debugging reference
        status: Optional remediation status (SUCCESS, FAILED, etc.) to determine formatting

    Returns:
        - dict: For successful remediation with structured output
        - str: For failure messages or plain text output
    """
    if not raw_output:
        return ""

    if control_runbook_status and control_runbook_status.upper() == "FAILED":
        return format_failure_message(raw_output, control_runbook_execution_id)

    try:
        parsed_output = json.loads(raw_output)
    except (json.JSONDecodeError, TypeError):
        return raw_output

    if not isinstance(parsed_output, dict):
        return raw_output

    # SSM Automation returns outputs as Map<String, List<String>>, meaning values are always
    # string arrays. Each step output contains exactly one element (at index 0) per the SSM API.
    # When remediation runbooks return JSON objects, they get stringified and stored as JSON
    # strings inside these single-element arrays, resulting in double-encoded JSON.
    # Example: {"Step.Output": ["{\"Message\":\"success\"}"]} needs a second decode pass
    # to become {"Step.Output": {"Message": "success"}} for human-readable display.
    formatted_output = {}
    for key, value in parsed_output.items():
        formatted_output[key] = value

        if isinstance(value, list) and value:
            try:
                formatted_output[key] = json.loads(value[0])
            except (json.JSONDecodeError, TypeError):
                pass

    return formatted_output


def format_details_for_output(details: Any) -> list[str]:
    """Handle various possible formats in the details"""
    from json.decoder import JSONDecodeError

    details_formatted = []
    if isinstance(details, list):
        details_formatted = details
    elif isinstance(details, str) and details[0:6] == "Cause:":
        try:
            details_formatted = json.dumps(json.loads(details[7:]), indent=2).split(
                "\n"
            )
        except JSONDecodeError:
            details_formatted.append(details[7:])
    elif isinstance(details, str):
        try:
            details_formatted = json.loads(details)
        except JSONDecodeError:
            details_formatted.append(details)
    else:
        details_formatted.append(details)

    return details_formatted


def _get_followup_message(control_id: str) -> str:
    """Return a structured manual follow-up message for remediations that require human action.

    GuardDuty and Macie remediations are first-line defenses — they contain or protect
    but do not fully resolve the underlying issue. This message is appended to the
    notification so recipients know what manual steps are required.

    Returns an empty string for controls that don't require manual follow-up.
    """
    if control_id == "GuardDuty.IAMUser":
        return (
            "\n\n--- MANUAL FOLLOW-UP REQUIRED ---\n"
            "CONTAINMENT ACTIONS COMPLETED:\n"
            "  - IAM access keys disabled\n"
            "  - Console access removed\n"
            "  - Deny-all policy attached\n\n"
            "REQUIRED NEXT STEPS:\n"
            "  1. Review CloudTrail logs for unauthorized activity during the compromise window\n"
            "  2. Assess the scope of any data access or exfiltration\n"
            "  3. Determine whether to restore or permanently revoke the IAM principal\n"
            "  4. Rotate any secrets or credentials the principal had access to\n"
            "  5. Use the Security Hub finding link to investigate and resolve the finding\n\n"
            "To restore the IAM principal, use the Rollback action on the ASR History page\n"
            "(available for GuardDuty remediations once the UI rollback feature is deployed).\n"
            "Note: IAM configuration backups are retained for 90 days."
        )
    if control_id == "Macie.SensitiveDataS3Object":
        return (
            "\n\n--- MANUAL FOLLOW-UP REQUIRED ---\n"
            "PROTECTION ACTIONS COMPLETED:\n"
            "  - S3 Block Public Access enabled (BlockPublicAcls, IgnorePublicAcls,\n"
            "    BlockPublicPolicy, RestrictPublicBuckets)\n\n"
            "REQUIRED NEXT STEPS:\n"
            "  1. Review the sensitive data finding in Security Hub to understand the data type\n"
            "  2. Assess the scope of potential exposure (who had access, for how long)\n"
            "  3. Determine whether the sensitive data should be deleted, encrypted, or relocated\n"
            "  4. Review compliance implications (GDPR, HIPAA, PCI-DSS) if applicable\n"
            "  5. Resolve the Security Hub finding once investigation and remediation are complete\n\n"
            "Block Public Access is a first-line defense. Review bucket policies and ACLs\n"
            "for additional access controls that may need to be tightened."
        )
    return ""


def set_message_prefix_and_suffix(event):
    message_prefix = event["Notification"].get("SSMExecutionId", "")
    message_suffix = event["Notification"].get("AffectedObject", "")
    if message_prefix:
        message_prefix += ": "
    if message_suffix:
        message_suffix = f" ({message_suffix})"
    return message_prefix, message_suffix


def _add_successful_remediation_metric_attributes(
    event: dict[str, Any], metrics_data: dict[str, Any]
) -> None:
    """Enriches the successful-remediation metric payload with the finding's first-detected
    time and notification/deadline configuration flags, read from the Findings table (where
    the Pre-Processor stamped them at ingestion). Best-effort: a missing finding, missing
    attributes, or a read error leaves the payload unchanged so metric publishing is never
    blocked.
    """
    try:
        finding_type = get_finding_type(event)
        finding_id = extract_finding_id(event)
        if not finding_type or not finding_id:
            return
        dynamodb = AWSCachedClient(AWS_REGION).get_connection("dynamodb")
        metrics_data.update(get_metric_attributes(dynamodb, finding_type, finding_id))
    except Exception as e:
        logger.warning(
            "Failed to enrich metrics with finding attributes, continuing",
            extra={"error": str(e)},
        )


def _process_metrics(
    event: dict[str, Any],
    status_from_event: str,
    control_id: str,
    custom_action_name: str,
) -> None:
    metrics = Metrics()
    metrics_data = metrics.get_metrics_from_event(event)
    metrics_data["status"], metrics_data["status_reason"] = (
        Metrics.get_status_for_metrics(status_from_event)
    )
    metrics_data["ai_generated"] = is_ai_generated_remediation(control_id)

    # Enrich only successful remediations (not rollbacks or failures) with the finding's
    # first-detected time and notification/deadline configuration, so leadership can compute
    # Mean Time To Remediate and correlate it with notification/deadline coverage.
    if metrics_data["status"] == "SUCCESS":
        _add_successful_remediation_metric_attributes(event, metrics_data)

    if metrics_data["status_reason"] == "REMEDIATION_FAILED":
        failure_message = event.get("Notification", {}).get("RemediationOutput", "")
        if failure_message:
            execution_id = event.get("Notification", {}).get("SSMExecutionId")
            metrics_data["failure_message"] = format_failure_message(
                failure_message, execution_id
            )

    # Emit RollbackAction metric when the event is a rollback completion.
    if custom_action_name == CUSTOM_ACTION_NAME_ROLLBACK:
        rollback_result = (
            "success" if status_from_event == "ROLLBACK_SUCCESS" else "failed"
        )
        failure_message = ""
        if rollback_result == "failed":
            failure_message = event.get("Notification", {}).get("Details") or event.get(
                "Notification", {}
            ).get("Message", "")
        metrics_data["RollbackAction"] = {
            "Result": rollback_result,
            "FailureMessage": failure_message,
            "FindingType": control_id or "Unknown",
        }

    metrics.send_metrics(metrics_data)

    create_and_send_cloudwatch_metrics(
        status_from_event, control_id, custom_action_name
    )


def _create_notification(
    event: Event,
    status_from_event: str,
    stepfunctions_execution_id: str,
    finding: Optional[sechub_findings.Finding],
) -> sechub_findings.ASRNotification:
    notification = sechub_findings.ASRNotification(
        event.get("SecurityStandard", "ASR"),
        AWS_REGION,
        stepfunctions_execution_id,
        event.get("ControlId", None),
    )

    if status_from_event in ("SUCCESS", "QUEUED", "ROLLBACK_SUCCESS"):
        notification.severity = "INFO"
    else:
        notification.severity = "ERROR"
        if finding:
            finding.flag(event["Notification"]["Message"])

    notification.send_to_sns = True
    return notification


def _resolve_history_resource_fields(
    event: Event, *, event_dict: dict[str, Any], finding_body: dict[str, Any]
) -> tuple[str, str, str]:
    """Resolve ``(resource_id, resource_type, resource_region)`` from an ASFF or OCSF finding.

    ``extract_resources`` only reads the ASFF capitalized ``Resources`` shape, so
    this falls back to the OCSF lowercase ``resources`` list and per-field OCSF
    keys, keeping the dual-shape handling out of ``_build_asff_for_history``.
    """
    resource = extract_resources(event) or {}
    if not resource:
        ocsf_resources = finding_body.get("resources")
        if isinstance(ocsf_resources, list) and ocsf_resources:
            resource = ocsf_resources[0]
    resource_id = extract_resource_id(event_dict, resource)
    if not resource_id:
        resource_id = resource.get("uid", "")  # OCSF resource id
    resource_type = resource.get("Type") or resource.get("type", "")
    resource_region = (
        resource.get("Region") or resource.get("region") or extract_region(event)
    )
    return resource_id, resource_type, resource_region


def _build_asff_for_history(event: Event) -> dict[str, Any]:
    """Synthesize an ASFF-shaped finding dict for the history `findingJSON` blob.

    The history-table blob is consumed by readers (rollback, IaC rendering,
    batch reconciliation) that all assume ASFF. ``event["Finding"]`` may be
    OCSF (multi-service auto-trigger) or ASFF, so the blob is rebuilt from the
    shared extractors (``extract_account_id``, ``extract_region``, etc.) which
    already handle both shapes. The result satisfies ``_is_asff_finding``.
    """
    event_dict: dict[str, Any] = dict(event)
    finding_body: dict[str, Any] = (
        event["Finding"] if isinstance(event.get("Finding"), dict) else {}
    )

    # ASFF/OCSF dual-shape field reads.
    title = finding_body.get("Title", "") or finding_body.get("finding_info", {}).get(
        "title", ""
    )
    description = finding_body.get("Description", "") or finding_body.get(
        "finding_info", {}
    ).get("desc", "")
    product_arn = finding_body.get("ProductArn", "") or (
        finding_body.get("metadata", {}).get("product", {}).get("uid", "")
    )

    resource_id, resource_type, resource_region = _resolve_history_resource_fields(
        event, event_dict=event_dict, finding_body=finding_body
    )

    # extract_severity reads only ASFF Severity.Label; OCSF puts it at top-level severity.
    severity_label = extract_severity(event) or finding_body.get("severity", "")

    control_id = extract_security_control_id(event_dict) or get_finding_type(event_dict)

    asff: dict[str, Any] = {
        "SchemaVersion": "2018-10-08",
        "Id": extract_finding_id(event_dict),
        "GeneratorId": control_id or "ASR",
        "ProductArn": product_arn,
        "AwsAccountId": resolve_finding_account_id(event),
        "Region": extract_region(event),
        "Title": title,
        "Description": description,
        "Severity": {"Label": severity_label},
        "Resources": [
            {
                "Id": resource_id,
                "Type": resource_type,
                "Region": resource_region,
            }
        ],
        "Compliance": {"SecurityControlId": control_id},
    }

    # Inspector drives patching off Vulnerabilities[0].VulnerablePackages[],
    # so the history blob must round-trip them in ASFF shape regardless of
    # ingestion format. Symmetric with toAsffShape in normalizedFindingAdapter.ts.
    asff_vulnerabilities = _coerce_vulnerabilities_to_asff(finding_body)
    if asff_vulnerabilities is not None:
        asff["Vulnerabilities"] = asff_vulnerabilities

    return asff


# ASFF shapes produced by the OCSF→ASFF translation below. Mirrors the
# AsffVulnerability/AsffVulnerablePackage TypedDicts consumed by the Inspector
# runbook (SC_Inspector.InstanceVulnerability.py) so the history blob round-trips.
class AsffVulnerablePackage(TypedDict):
    Name: str
    Architecture: str
    Version: str


class AsffVulnerability(TypedDict):
    Id: str
    FixAvailable: str
    VulnerablePackages: list[AsffVulnerablePackage]


def _coerce_vulnerabilities_to_asff(
    finding_body: dict[str, Any],
) -> list[AsffVulnerability] | None:
    """Return Vulnerabilities[] in ASFF shape, or None if the finding has none.

    ASFF input passes through; OCSF ``vulnerabilities[]`` is translated
    element-wise (inverse of ``_asff_vulnerability_to_internal`` in the runbook).
    """
    asff_vulnerabilities = finding_body.get("Vulnerabilities")
    if isinstance(asff_vulnerabilities, list):
        return asff_vulnerabilities

    ocsf_vulnerabilities = finding_body.get("vulnerabilities")
    if not isinstance(ocsf_vulnerabilities, list):
        return None

    return [
        _translate_ocsf_vulnerability(vulnerability)
        for vulnerability in ocsf_vulnerabilities
        if isinstance(vulnerability, dict)
    ]


def _translate_ocsf_packages(ocsf_packages: object) -> list[AsffVulnerablePackage]:
    """Translate an OCSF ``affected_packages`` list into ASFF ``VulnerablePackages``."""
    if not isinstance(ocsf_packages, list):
        return []
    return [
        {
            "Name": pkg.get("name", ""),
            "Architecture": pkg.get("architecture", ""),
            "Version": pkg.get("version", ""),
        }
        for pkg in ocsf_packages
        if isinstance(pkg, dict)
    ]


def _translate_ocsf_vulnerability(vulnerability: dict[str, Any]) -> AsffVulnerability:
    """Translate a single OCSF vulnerability into ASFF shape.

    Inverse of ``_asff_vulnerability_to_internal`` in the Inspector runbook.
    """
    cve_raw = vulnerability.get("cve")
    cve = cve_raw if isinstance(cve_raw, dict) else {}
    # OCSF bool → ASFF "YES"/"NO"; only "YES" maps to fixable in the runbook.
    fix_available = "YES" if vulnerability.get("is_fix_available") is True else "NO"
    return {
        "Id": cve.get("uid", ""),
        "FixAvailable": fix_available,
        "VulnerablePackages": _translate_ocsf_packages(
            vulnerability.get("affected_packages")
        ),
    }


def _non_empty_str(value: object) -> str | None:
    """A value the Notification carries only sometimes, normalised to str or None."""
    return value if isinstance(value, str) and value else None


def _compress_finding_for_history(event: Event) -> bytes | None:
    try:
        return gzip.compress(json.dumps(_build_asff_for_history(event)).encode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        logger.warning(
            "Failed to compress finding for IaC rendering; proceeding without",
            extra={"error": str(exc)},
        )
        return None


def _update_finding_remediation_status(
    execution_id: str,
    status_from_event: str,
    event: Event,
) -> None:
    event_dict = cast(dict[str, Any], cast(object, event))
    remediation_status = map_remediation_status(status_from_event)
    error_message = None

    # Capture the reason on rollback failures too, so the history `error` field shows why.
    if remediation_status in ("FAILED", "ROLLBACK_FAILED"):
        raw_error = event["Notification"].get("Details") or event["Notification"].get(
            "Message"
        )
        error_message = extract_failure_reason(raw_error) if raw_error else None

    if is_resolved_item(event):
        logger.warning(
            "Overriding remediation status to SUCCESS for resolved workflow with NOT_NEW state",
            extra={
                "findingId": extract_finding_id(event_dict),
                "originalStatus": status_from_event,
                "overriddenStatus": "SUCCESS",
            },
        )
        remediation_status = "SUCCESS"
        error_message = None

    finding_id = extract_finding_id(event_dict)
    finding_type = get_finding_type(event_dict)

    logger.debug(
        "Finding processing",
        extra={
            "finding id": finding_id,
            "finding type": finding_type,
        },
    )

    try:
        resources = extract_resources(event)

        # Capture the GuardDuty Contain backup key (if present) so a later
        # rollback can supply it to AWSSupport-ContainIAMPrincipal.
        backup_s3_key = _non_empty_str(event["Notification"].get("BackupS3Key"))

        # Capture the SSM Automation execution ID so the rollback API can
        # locate the pre-remediation snapshot in S3 (keyed by this ID).
        ssm_execution_id = _non_empty_str(event["Notification"].get("SSMExecutionId"))

        # Skip on non-SUCCESS — IaC links and rollback only fire on successful remediations.
        finding_json: bytes | None = None
        if remediation_status == "SUCCESS" and event.get("Finding"):
            finding_json = _compress_finding_for_history(event)

        rollback_available, rollback_description, snapshot_version_id = (
            _resolve_rollback_state(event, event_dict, remediation_status)
        )

        if remediation_status == "ROLLBACK_SUCCESS" and event.get("Finding"):
            _reset_finding_workflow_status(event)
            # Mark rollback as consumed so the UI hides the rollback button.
            # _resolve_rollback_state returns None for non-SUCCESS statuses,
            # so this explicit False is what persists to DynamoDB.
            rollback_available = False
        elif remediation_status == "ROLLBACK_FAILED":
            rollback_available = True

        remediation_request = RemediationUpdateRequest(
            finding_id=finding_id,
            execution_id=execution_id,
            remediation_status=remediation_status,
            finding_type=finding_type,
            error=error_message,
            resource_id=extract_resource_id(event_dict, resources),
            resource_type=resources.get("Type", ""),
            account_id=resolve_finding_account_id(event),
            # Raw severity for the persisted record (no CRITICAL fallback) — the
            # notification path applies its own fallback for filtering purposes.
            severity=extract_severity(event),
            region=extract_region(event),
            last_updated_by=extract_triggered_by(event),
            finding_json=finding_json,
            # Persisted only on a successful GuardDuty Contain so a later rollback
            # can supply the backup key to AWSSupport-ContainIAMPrincipal.
            backup_s3_key=backup_s3_key,
            ssm_execution_id=ssm_execution_id,
            rollback_available=rollback_available,
            rollback_description=rollback_description,
            snapshot_version_id=snapshot_version_id,
        )
        update_remediation_status_and_history(remediation_request)
    except Exception as e:
        logger.error(
            "Failed to update remediation status and history",
            extra={
                "finding_id": finding_id,
                "executionId": execution_id,
                "finding_type": finding_type,
                "error": str(e),
            },
        )


def _try_transform_stepfunctions_event(
    event: Event | dict[str, Any],
) -> Event | dict[str, Any]:
    """Attempt to transform a Step Functions failure event into the standard Event shape.

    Returns the original event unchanged if it is not a Step Functions event or
    if the transformation fails.
    """
    try:
        if (
            isinstance(event, dict)
            and event.get("detail-type") == "Step Functions Execution Status Change"
        ):
            raw_event = cast(dict[str, Any], event)
            logger.info(
                "Processing Step Functions failure event",
                extra={
                    "executionArn": raw_event.get("detail", {}).get("executionArn", ""),
                    "status": raw_event.get("detail", {}).get("status", ""),
                },
            )
            return transform_stepfunctions_failure_event(raw_event)
    except Exception as e:
        logger.error(
            "Failed to transform event - continuing with original",
            extra={"error": str(e)},
        )
    return event


# Canonical remediation event statuses recognized by downstream consumers.
# The SUCCESS/FAILED/QUEUED values come straight from SSM. ROLLBACK_SUCCESS and
# ROLLBACK_FAILED are synthesized by _resolve_event_status when the user-triggered
# action was a rollback. Other SSM states (TIMEDOUT, LAMBDA_ERROR,
# ASSUME_ROLE_FAILURE, etc.) flow through unchanged and are folded into FAILED by
# map_remediation_status downstream.
RecognizedRemediationStatus = Literal[
    "SUCCESS", "FAILED", "QUEUED", "ROLLBACK_SUCCESS", "ROLLBACK_FAILED"
]


def _resolve_event_status(event: Event) -> str:
    """Resolve the canonical remediation status string for downstream consumers.

    Pure function: derives the status from the inbound Step Functions event and
    the user's chosen action. When the user triggered a Rollback (signaled via
    ``CustomActionName == CUSTOM_ACTION_NAME_ROLLBACK``), the underlying SSM
    outcome is mapped to a distinct rollback status: ``ROLLBACK_SUCCESS`` on
    success and ``ROLLBACK_FAILED`` on any terminal failure. The distinct status
    keeps the DDB history, SQS notification event, SNS email, and metrics
    consumers aligned on the rollback outcome, and on the API side the terminal
    write releases the optimistic rollback lock.

    Returns the uppercased ``Notification.State`` for non-rollback events.
    Recognized canonical values are listed in
    :data:`RecognizedRemediationStatus`; other SSM states (e.g. ``TIMEDOUT``,
    ``LAMBDA_ERROR``, ``ASSUME_ROLE_FAILURE``) are passed through uppercased and
    resolved downstream by ``map_remediation_status``. Returns an empty string
    when ``Notification.State`` is missing.
    """
    raw_status = event.get("Notification", {}).get("State", "").upper()
    if event.get("CustomActionName") == CUSTOM_ACTION_NAME_ROLLBACK:
        if raw_status == "SUCCESS":
            return "ROLLBACK_SUCCESS"
        # Any terminal non-success outcome of a rollback is a rollback failure.
        # QUEUED is mid-flight (not terminal) and the empty string means no state
        # was reported, so leave both untouched and let downstream handle them.
        if raw_status not in ("QUEUED", ""):
            return "ROLLBACK_FAILED"
    return raw_status


@tracer.capture_lambda_handler  # type: ignore[untyped-decorator]
def lambda_handler(event: Event | dict[str, Any], context: Any) -> None:
    event = _try_transform_stepfunctions_event(event)

    # Type assertion: at this point, event should be of type Event
    event = cast(Event, event)

    message_prefix, message_suffix = set_message_prefix_and_suffix(event)
    stepfunctions_execution_id = extract_stepfunctions_execution_id(event)
    status_from_event = _resolve_event_status(event)

    event_dict = cast(dict[str, Any], cast(object, event))
    finding, finding_info = extract_finding_info(event_dict)

    control_id = extract_security_control_id(event_dict)
    custom_action_name = event.get("CustomActionName", "")

    _process_metrics(event_dict, status_from_event, control_id, custom_action_name)

    notification = _create_notification(
        event, status_from_event, stepfunctions_execution_id, finding
    )

    notified_workflow = is_notified_workflow(event)

    # Try the status update first. If it fails, we still want to send the
    # notification, so we use try/finally to guarantee both the SQS notification
    # event and SNS/email notification are sent regardless. Only resolve the
    # finding on the success path (no pending exception).
    try:
        if "Finding" in event and not notified_workflow:
            _update_finding_remediation_status(
                stepfunctions_execution_id, status_from_event, event
            )
    except Exception:
        logger.exception(
            "Failed to update remediation status, will send notification then re-raise",
        )
        raise
    else:
        # Only mark the Security Hub finding as RESOLVED on a remediation
        # SUCCESS — rollbacks restore state and should not resolve the finding.
        if status_from_event == "SUCCESS" and finding:
            finding.resolve(event["Notification"]["Message"])
    finally:
        _publish_notification_event(
            event,
            status_from_event,
            finding_info=finding_info if isinstance(finding_info, dict) else None,
        )
        build_and_send_notification(
            event, notification, message_prefix, message_suffix, finding_info
        )


def build_and_send_notification(
    event: Event,
    notification: sechub_findings.ASRNotification,
    message_prefix: str,
    message_suffix: str,
    finding_info: Union[str, FindingInfo],
) -> None:
    notification.message = (
        message_prefix + event["Notification"]["Message"] + message_suffix
    )

    # Append structured follow-up instructions for remediations that require manual action
    control_id = event.get("ControlId", "")
    followup = _get_followup_message(control_id)
    if followup:
        notification.message += followup

    notification.remediation_output = format_remediation_output(
        event["Notification"].get("RemediationOutput", ""),
        event["Notification"].get("SSMExecutionId"),
        event["Notification"].get("State"),
    )

    notification.remediation_status = event["Notification"]["State"]

    remediation_account_id = ""
    if isinstance(finding_info, dict):
        remediation_account_id = (
            finding_info["account"] if "account" in finding_info else ""
        )
        notification.finding_link = get_security_hub_console_url(
            finding_info["finding_arn"]
        )

    try:
        notification.remediation_account_alias = get_account_alias(
            remediation_account_id
        )
    except Exception as e:
        logger.warning(
            f"Unexpected error getting account alias for {remediation_account_id}, using account ID",
            extra={"accountId": remediation_account_id, "error": str(e)},
        )
        notification.remediation_account_alias = remediation_account_id or "Unknown"

    if (
        "Details" in event["Notification"]
        and event["Notification"]["Details"] != "MISSING"
    ):
        notification.logdata = format_details_for_output(
            event["Notification"]["Details"]
        )

    if "GenerateTicket" in event and event["GenerateTicket"]:
        generate_ticket_response = event["GenerateTicket"]
        response_reason = generate_ticket_response["ResponseReason"]
        notification.ticket_url = (
            generate_ticket_response["TicketURL"]
            if generate_ticket_response["Ok"]
            else f"Error generating ticket: {response_reason} - check ticket_generator lambda logs for details"
        )

    notification.finding_info = finding_info  # type: ignore[assignment]
    notification.notify()


def create_and_send_cloudwatch_metrics(
    event_state: str, control_id: str, custom_action_name: Union[None, str]
) -> None:
    try:
        cloudwatch_metrics = CloudWatchMetrics()

        control_id = control_id or "Unknown"

        dimensions = [
            {
                "Name": "Outcome",
                "Value": event_state,
            },
        ]
        if os.environ["ENHANCED_METRICS"].lower() == "yes":
            enhanced_metric = {
                "MetricName": "RemediationOutcome",
                "Dimensions": [*dimensions, {"Name": "ControlId", "Value": control_id}],
                "Unit": "Count",
                "Value": 1,
            }
            cloudwatch_metrics.send_metric(enhanced_metric)
        if custom_action_name:
            custom_action_metric = {
                "MetricName": "RemediationOutcome",
                "Dimensions": [
                    *dimensions,
                    {"Name": "CustomActionName", "Value": custom_action_name},
                ],
                "Unit": "Count",
                "Value": 1,
            }
            cloudwatch_metrics.send_metric(custom_action_metric)
        cloudwatch_metric = {
            "MetricName": "RemediationOutcome",
            "Dimensions": dimensions,
            "Unit": "Count",
            "Value": 1,
        }
        cloudwatch_metrics.send_metric(cloudwatch_metric)

        _emit_multi_service_metrics(
            cloudwatch_metrics, event_state, control_id, custom_action_name
        )
    except Exception as e:
        logger.debug(f"Encountered error sending Cloudwatch metric: {str(e)}")


# Multi-service remediation identifiers. Controls in this set emit additional
# metrics with ServiceType dimensions for per-service analysis.
MULTI_SERVICE_CONTROLS: frozenset[str] = frozenset(
    {
        "GuardDuty.IAMUser",
        "Inspector.InstanceVulnerability",
        "Macie.SensitiveDataS3Object",
        "IAMAccessAnalyzer.ExternalAccess",
    }
)


def _get_service_type(control_id: str) -> str:
    """Extract the service name from a multi-service control ID (e.g. 'GuardDuty' from 'GuardDuty.IAMUser')."""
    return control_id.split(".")[0] if "." in control_id else control_id


def _resolve_rollback_state(
    event: Event,
    event_dict: dict[str, Any],
    remediation_status: str,
) -> tuple[bool | None, str | None, str | None]:
    """Orchestrate rollback metadata extraction and metric emission.

    Returns (rollback_available, rollback_description, snapshot_version_id).
    """
    control_id = extract_security_control_id(event_dict) or ""
    is_rollback_enabled = os.environ.get("ENABLE_ROLLBACK", "no") == "yes" and (
        not control_id or _is_control_rollback_enabled(control_id)
    )

    rollback_available: bool | None = None
    rollback_description: str | None = None
    snapshot_version_id: str | None = None

    if is_rollback_enabled and remediation_status == "SUCCESS":
        rollback_available, rollback_description, snapshot_version_id = (
            _extract_rollback_metadata(event)
        )

    should_emit_metrics = is_rollback_enabled and (
        remediation_status == "SUCCESS"
        or remediation_status in ("ROLLBACK_SUCCESS", "ROLLBACK_FAILED")
    )
    if should_emit_metrics:
        _emit_rollback_metrics(
            cloudwatch_metrics=CloudWatchMetrics(),
            control_id=control_id or "Unknown",
            event_state=remediation_status,
            rollback_available=rollback_available,
        )

    return rollback_available, rollback_description, snapshot_version_id


def _extract_rollback_metadata(
    event: Event,
) -> tuple[bool | None, str | None, str | None]:
    """Parse remediation output for snapshot metadata.

    Returns (rollback_available, rollback_description, snapshot_version_id).
    """
    remediation_output_raw = event["Notification"].get("RemediationOutput", "")
    if not remediation_output_raw:
        return None, None, None
    try:
        remediation_output = (
            json.loads(remediation_output_raw)
            if isinstance(remediation_output_raw, str)
            else remediation_output_raw
        )
        if not isinstance(remediation_output, dict):
            return None, None, None

        snapshot_stored = _get_output_field(remediation_output, "snapshotStored")
        if snapshot_stored is None:
            return None, None, None
        if snapshot_stored == "true":
            return (
                True,
                _get_output_field(remediation_output, "rollbackDescription") or "",
                _get_output_field(remediation_output, "snapshotVersionId"),
            )
        return False, None, None
    except (json.JSONDecodeError, TypeError):
        logger.debug(
            "RemediationOutput is not JSON or does not contain snapshot info",
            extra={"output": str(remediation_output_raw)[:200]},
        )
        return None, None, None


def _reset_finding_workflow_status(event: Event) -> None:
    """Reset Security Hub finding WorkflowStatus to NEW after successful rollback."""
    finding_id_for_sechub = ""
    try:
        finding = event["Finding"]
        finding_id_for_sechub = finding.get("Id", "")
        product_arn = finding.get("ProductArn", "")
        if finding_id_for_sechub and product_arn:
            _get_sechub_client().batch_update_findings(
                FindingIdentifiers=[
                    {"Id": finding_id_for_sechub, "ProductArn": product_arn}
                ],
                Workflow={"Status": "NEW"},
                Note={
                    "Text": "ASR rollback completed. WorkflowStatus reset to NEW for re-evaluation.",
                    "UpdatedBy": "ASR-Rollback",
                },
            )
            logger.info(
                "Reset Security Hub WorkflowStatus to NEW after rollback",
                extra={"findingId": finding_id_for_sechub},
            )
    except Exception as sechub_err:
        logger.warning(
            "Failed to reset finding WorkflowStatus to NEW after rollback",
            extra={"findingId": finding_id_for_sechub, "error": str(sechub_err)},
        )


def _rollback_dimension_sets(
    control_id: str, is_enhanced_metrics: bool, extra: list[dict[str, str]]
) -> list[list[dict[str, str]]]:
    """Dimension sets for a rollback metric: always the ControlId-free aggregate
    the alarms watch, plus the per-ControlId breakdown only under ENHANCED_METRICS."""
    aggregate: list[dict[str, str]] = list(extra)
    if not is_enhanced_metrics:
        return [aggregate]
    return [[{"Name": "ControlId", "Value": control_id}, *extra], aggregate]


def _emit_snapshot_capture_metric(
    cloudwatch_metrics: CloudWatchMetrics,
    control_id: str,
    event_state: str,
    rollback_available: bool | None,
    is_enhanced_metrics: bool,
) -> None:
    """Snapshot-capture outcome for a SUCCESS remediation: captured, failed, or skipped."""
    if rollback_available is True:
        if is_enhanced_metrics:
            cloudwatch_metrics.send_metric(
                {
                    "MetricName": "SnapshotCaptureSuccess",
                    "Dimensions": [{"Name": "ControlId", "Value": control_id}],
                    "Unit": "Count",
                    "Value": 1,
                }
            )
    elif rollback_available is False:
        for dimensions in _rollback_dimension_sets(control_id, is_enhanced_metrics, []):
            cloudwatch_metrics.send_metric(
                {
                    "MetricName": "SnapshotCaptureFailure",
                    "Dimensions": dimensions,
                    "Unit": "Count",
                    "Value": 1,
                }
            )
    elif event_state == "SUCCESS" and is_enhanced_metrics:
        cloudwatch_metrics.send_metric(
            {
                "MetricName": "SnapshotCaptureSkipped",
                "Dimensions": [{"Name": "ControlId", "Value": control_id}],
                "Unit": "Count",
                "Value": 1,
            }
        )


def _emit_rollback_execution_metric(
    cloudwatch_metrics: CloudWatchMetrics,
    control_id: str,
    event_state: str,
    is_enhanced_metrics: bool,
) -> None:
    """RollbackExecutionOutcome for a ROLLBACK_SUCCESS / ROLLBACK_FAILED event."""
    if event_state not in ("ROLLBACK_SUCCESS", "ROLLBACK_FAILED"):
        return
    rollback_outcome = "Success" if event_state == "ROLLBACK_SUCCESS" else "Failed"
    for dimensions in _rollback_dimension_sets(
        control_id,
        is_enhanced_metrics,
        [{"Name": "Outcome", "Value": rollback_outcome}],
    ):
        cloudwatch_metrics.send_metric(
            {
                "MetricName": "RollbackExecutionOutcome",
                "Dimensions": dimensions,
                "Unit": "Count",
                "Value": 1,
            }
        )


def _emit_rollback_metrics(
    cloudwatch_metrics: CloudWatchMetrics,
    control_id: str,
    event_state: str,
    rollback_available: bool | None,
) -> None:
    """Emit snapshot-capture and rollback-execution CloudWatch metrics.

    Alarm-backing series (SnapshotCaptureFailure, RollbackExecutionOutcome) are
    emitted both per-ControlId and as a ControlId-free aggregate the alarms
    watch, since a CloudWatch alarm cannot roll a per-ControlId series up across
    controls (no SEARCH). Per-ControlId series are gated on ENHANCED_METRICS.
    """
    try:
        control_id = control_id or "Unknown"
        is_enhanced_metrics = os.environ.get("ENHANCED_METRICS", "no").lower() == "yes"
        _emit_snapshot_capture_metric(
            cloudwatch_metrics,
            control_id,
            event_state,
            rollback_available,
            is_enhanced_metrics,
        )
        _emit_rollback_execution_metric(
            cloudwatch_metrics, control_id, event_state, is_enhanced_metrics
        )
    except Exception as e:
        logger.debug(
            "Failed to emit rollback metrics",
            extra={"error": str(e)},
        )


def _emit_multi_service_metrics(
    cloudwatch_metrics: CloudWatchMetrics,
    event_state: str,
    control_id: str,
    custom_action_name: str | None,
) -> None:
    """Emit RemediationAttempt and RollbackOutcome metrics for multi-service finding types."""
    if control_id not in MULTI_SERVICE_CONTROLS:
        return

    service_type = _get_service_type(control_id)

    cloudwatch_metrics.send_metric(
        {
            "MetricName": "RemediationAttempt",
            "Dimensions": [
                {"Name": "ServiceType", "Value": service_type},
                {"Name": "FindingType", "Value": control_id},
                {"Name": "Outcome", "Value": event_state},
            ],
            "Unit": "Count",
            "Value": 1,
        }
    )

    if custom_action_name == CUSTOM_ACTION_NAME_ROLLBACK:
        rollback_outcome = "Success" if event_state == "ROLLBACK_SUCCESS" else "Failed"
        cloudwatch_metrics.send_metric(
            {
                "MetricName": "RollbackOutcome",
                "Dimensions": [
                    {"Name": "ServiceType", "Value": service_type},
                    {"Name": "FindingType", "Value": control_id},
                    {"Name": "Outcome", "Value": rollback_outcome},
                ],
                "Unit": "Count",
                "Value": 1,
            }
        )
