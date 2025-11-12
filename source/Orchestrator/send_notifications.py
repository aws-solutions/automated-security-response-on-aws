# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from json.decoder import JSONDecodeError
from typing import Any, NotRequired, Optional, TypedDict, Union, cast
from urllib.parse import quote_plus

from botocore.exceptions import ClientError
from layer import sechub_findings
from layer.awsapi_cached_client import AWSCachedClient
from layer.cloudwatch_metrics import CloudWatchMetrics
from layer.metrics import NORMALIZED_STATUS_REASON_MAPPING, Metrics
from layer.powertools_logger import get_logger
from layer.tracer_utils import init_tracer
from layer.utils import get_account_alias

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")  # MUST BE SET in global variables
AWS_PARTITION = os.getenv("AWS_PARTITION", "aws")  # MUST BE SET in global variables


def get_console_host(partition: str) -> str:
    console_hosts = {
        "aws": "console.aws.amazon.com",
        "aws-us-gov": "console.amazonaws-us-gov.com",
        "aws-cn": "console.amazonaws.cn",
    }
    return console_hosts.get(partition, console_hosts["aws"])


def get_security_hub_console_url(
    finding_id: str, region: Optional[str] = None, partition: Optional[str] = None
) -> str:
    """Generates Security Hub finding console URL.

    If Security Hub V2 is enabled in the current account, this finding links to
    the Security Hub console. Otherwise, it links to Security Hub CSPM.

    Args:
        finding_id: The Security Hub finding ID
        region: AWS region (optional, defaults to AWS_REGION env var). Since the solution
            must be deployed in the Security Hub aggregation region, all findings should be
            available in the region where this Lambda function exists, meaning you likely do
            not want to pass a value for this parameter unless you require a region-specific
            console link.
        partition: AWS partition (optional, defaults to AWS_PARTITION env var)

    Returns:
        Console URL for the Security Hub finding
    """
    securityhub_v2_enabled = (
        os.getenv("SECURITY_HUB_V2_ENABLED", "false").lower() == "true"
    )
    aws_region = region or os.getenv("AWS_REGION", "us-east-1")
    aws_partition = partition or cast(str, os.getenv("AWS_PARTITION", "aws"))

    host = get_console_host(aws_partition)

    if securityhub_v2_enabled:
        default_url = f"/securityhub/v2/home?region={aws_region}#/findings?search=finding_info.uid%3D%255Coperator%255C%253AEQUALS%255C%253A{quote_plus(finding_id)}"
    else:
        default_url = f"/securityhub/home?region={aws_region}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A{quote_plus(finding_id)}"

    url_pattern = os.getenv("CONSOLE_URL_PATTERN", default_url)

    return f"https://{host}{url_pattern}"


logger = get_logger("send_notifications")
tracer = init_tracer()

FINDINGS_TABLE_NAME = os.getenv("FINDINGS_TABLE_NAME", "")
HISTORY_TABLE_NAME = os.getenv("HISTORY_TABLE_NAME", "")

FINDING_ID_EXECUTION_ID_KEY = "findingId#executionId"
SORT_KEY_ATTRIBUTE_NAME = "#sortKey"


class FindingData(TypedDict, total=False):
    accountId: str
    resourceId: str
    resourceType: str
    resourceTypeNormalized: str
    severity: str
    region: str
    lastUpdatedBy: str


class FindingInfo(TypedDict):
    finding_id: str
    finding_description: str
    standard_name: str
    standard_version: str
    standard_control: str
    title: str
    region: str
    account: str
    finding_arn: str


class TransactWriteItem(TypedDict, total=False):
    Put: dict[str, Any]
    Update: dict[str, Any]
    Delete: dict[str, Any]
    ConditionCheck: dict[str, Any]


def calculate_history_ttl_timestamp(timestamp: str) -> int:
    ttl_days = int(os.getenv("HISTORY_TTL_DAYS", "365"))

    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    ttl_dt = dt + timedelta(days=ttl_days)
    return int(ttl_dt.timestamp())


@dataclass
class RemediationUpdateRequest:
    finding_id: str
    execution_id: str
    remediation_status: str
    finding_type: str
    error: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    account_id: Optional[str] = None
    severity: Optional[str] = None
    region: Optional[str] = None
    lastUpdatedBy: Optional[str] = "Automated"

    def validate(self) -> bool:
        if not self.finding_id or not self.execution_id or not self.finding_type:
            logger.error(
                "Missing required parameters",
                extra={
                    "findingId": self.finding_id,
                    "executionId": self.execution_id,
                    "findingType": self.finding_type,
                },
            )
            return False

        return True


def format_details_for_output(details: Any) -> list[str]:
    """Handle various possible formats in the details"""
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


def set_message_prefix_and_suffix(event):
    message_prefix = event["Notification"].get("SSMExecutionId", "")
    message_suffix = event["Notification"].get("AffectedObject", "")
    if message_prefix:
        message_prefix += ": "
    if message_suffix:
        message_suffix = f" ({message_suffix})"
    return message_prefix, message_suffix


def map_remediation_status(status: Optional[str]) -> str:
    if not status:
        return "NOT_STARTED"

    status_upper = status.upper()

    if status_upper in ("SUCCESS", "NOT_STARTED"):
        return status_upper

    if status_upper in ("QUEUED", "RUNNING", "IN_PROGRESS"):
        return "IN_PROGRESS"

    if status_upper in list(NORMALIZED_STATUS_REASON_MAPPING.keys()):
        logger.debug(
            f"Mapping original failed remediation status {status_upper} to 'FAILED'"
        )
        return "FAILED"

    logger.warning(f"Unknown remediation status '{status}', mapping to FAILED")
    return "FAILED"


class Notification(TypedDict):
    Message: str
    State: str
    Details: NotRequired[str]
    RemediationOutput: NotRequired[str]
    StepFunctionsExecutionId: NotRequired[str]
    SSMExecutionId: NotRequired[str]


class GenerateTicket(TypedDict):
    TicketURL: str
    Ok: bool
    ResponseCode: str
    ResponseReason: str


class Event(TypedDict):
    Notification: Notification
    Finding: dict[str, Any]
    EventType: NotRequired[str]
    GenerateTicket: NotRequired[GenerateTicket]
    CustomActionName: NotRequired[str]
    SecurityStandard: NotRequired[str]
    ControlId: NotRequired[str]
    AccountId: NotRequired[str]
    Region: NotRequired[str]
    Resources: NotRequired[Union[list[dict[str, Any]], dict[str, Any]]]
    Severity: NotRequired[dict[str, Any]]


def update_remediation_status_and_history(request: RemediationUpdateRequest) -> None:

    if not request.validate():
        return

    try:
        aws_client = AWSCachedClient(AWS_REGION)
        dynamodb = aws_client.get_connection("dynamodb")

        logger.debug(
            "Processing remediation status update",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "remediationStatus": request.remediation_status,
                "error": request.error,
            },
        )

        # First, try to update both finding and history
        success = _try_update_with_existing_history(dynamodb, request)

        if not success:
            logger.info(
                "History item not found, creating new history record via fallback",
                extra={
                    "findingId": request.finding_id,
                    "executionId": request.execution_id,
                    "findingType": request.finding_type,
                    "remediationStatus": request.remediation_status,
                },
            )
            _create_history_with_finding_update(dynamodb, request)

    except ClientError as e:
        logger.error(
            "Failed to update remediation status",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "error": str(e),
            },
        )
        raise
    except Exception as e:
        logger.error(
            "Unexpected error updating remediation status",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "error": str(e),
            },
        )
        raise


def _try_update_with_existing_history(
    dynamodb: Any,
    request: RemediationUpdateRequest,
) -> bool:
    try:
        logger.debug(
            "Attempting to update existing history item",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "remediationStatus": request.remediation_status,
            },
        )

        transact_items = []

        finding_update_item = _build_finding_update_item(
            request.finding_type,
            request.finding_id,
            request.remediation_status,
            request.execution_id,
            request.error,
        )
        transact_items.append(finding_update_item)

        remediation_history_item = _build_history_update_item(request)
        transact_items.append(remediation_history_item)

        dynamodb.transact_write_items(TransactItems=transact_items)

        logger.debug(
            "Successfully updated existing history item via transaction",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "remediationStatus": request.remediation_status,
            },
        )
        return True

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")

        logger.warning(
            "Transaction failed while trying to update existing history",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "remediationStatus": request.remediation_status,
                "errorCode": error_code,
                "errorMessage": str(e),
            },
        )

        # Check if the error is due to conditional check failure (history item doesn't exist)
        if error_code == "TransactionCanceledException":
            cancellation_reasons = e.response.get("CancellationReasons", [])
            for i, reason in enumerate(cancellation_reasons):
                if reason.get("Code") == "ConditionalCheckFailed":
                    logger.warning(
                        "History item not found due to conditional check failure, will attempt fallback creation",
                        extra={
                            "findingId": request.finding_id,
                            "executionId": request.execution_id,
                            "findingType": request.finding_type,
                            "remediationStatus": request.remediation_status,
                            "cancellationReason": reason,
                            "transactionItemIndex": i,
                        },
                    )
                    return False

        raise


def _create_history_with_finding_update(
    dynamodb: Any,
    request: RemediationUpdateRequest,
) -> None:
    finding_data = None

    try:
        finding_data = _get_finding_data(
            dynamodb, request.finding_type, request.finding_id
        )
    except Exception as e:
        logger.warning(
            "Could not retrieve finding data for history creation, proceeding with minimal data",
            extra={
                "findingId": request.finding_id,
                "error": str(e),
            },
        )

    try:
        transact_items = []

        if finding_data:
            finding_update_item = _build_finding_update_item(
                request.finding_type,
                request.finding_id,
                request.remediation_status,
                request.execution_id,
                request.error,
            )
            transact_items.append(finding_update_item)

        history_create_item = _build_history_create_item(request, finding_data)
        transact_items.append(history_create_item)

        dynamodb.transact_write_items(TransactItems=transact_items)

        logger.info(
            "Successfully created remediation history via fallback",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
            },
        )

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")

        if error_code == "TransactionCanceledException":
            _update_finding_only(dynamodb, request)
        else:
            raise


def _update_finding_only(
    dynamodb: Any,
    request: RemediationUpdateRequest,
) -> None:
    try:
        finding_update_item = _build_finding_update_item(
            request.finding_type,
            request.finding_id,
            request.remediation_status,
            request.execution_id,
            request.error,
        )

        dynamodb.transact_write_items(TransactItems=[finding_update_item])

        logger.debug(
            "Successfully updated finding only after history operation failure",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
            },
        )
    except Exception as e:
        logger.error(
            "Failed to update finding after history operation failure",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "error": str(e),
            },
        )
        raise


def _extract_finding_fields(item: dict[str, Any]) -> FindingData:
    finding_data: FindingData = {}
    field_mappings = [
        "accountId",
        "resourceId",
        "resourceType",
        "resourceTypeNormalized",
        "severity",
        "region",
        "lastUpdatedBy",
    ]

    for field in field_mappings:
        if field in item:
            finding_data[field] = item[field]["S"]  # type: ignore[literal-required]

    return finding_data


def _get_finding_data(
    dynamodb: Any,
    finding_type: str,
    finding_id: str,
) -> Optional[FindingData]:
    try:
        response = dynamodb.get_item(
            TableName=FINDINGS_TABLE_NAME,
            Key={
                "findingType": {"S": finding_type},
                "findingId": {"S": finding_id},
            },
        )

        if "Item" not in response:
            return None

        return _extract_finding_fields(response["Item"])

    except Exception as e:
        logger.warning(
            "Error retrieving finding data",
            extra={
                "findingType": finding_type,
                "findingId": finding_id,
                "error": str(e),
            },
        )
        return None


def _build_finding_update_item(
    finding_type: str,
    finding_id: str,
    remediation_status: str,
    execution_id: str,
    error: Optional[str] = None,
) -> TransactWriteItem:
    update_expression = "SET remediationStatus = :rs"
    expression_values = {
        ":rs": {"S": remediation_status},
    }
    expression_names = {}

    if execution_id:
        update_expression += ", executionId = :eid"
        expression_values[":eid"] = {"S": execution_id}

    if error:
        update_expression += ", #err = :err"
        expression_names["#err"] = "error"
        expression_values[":err"] = {"S": error}

    finding_update_item: TransactWriteItem = {
        "Update": {
            "TableName": FINDINGS_TABLE_NAME,
            "Key": {"findingType": {"S": finding_type}, "findingId": {"S": finding_id}},
            "UpdateExpression": update_expression,
            "ExpressionAttributeValues": expression_values,
        }
    }

    if expression_names:
        finding_update_item["Update"]["ExpressionAttributeNames"] = expression_names

    return finding_update_item


def _merge_finding_data_into_item(
    item: dict[str, Any], finding_data: FindingData
) -> None:
    field_mappings = [
        "accountId",
        "resourceId",
        "resourceType",
        "resourceTypeNormalized",
        "severity",
        "region",
        "lastUpdatedBy",
    ]

    for field in field_mappings:
        if field in finding_data:
            item[field] = {"S": finding_data[field]}  # type: ignore[literal-required]


def _build_history_create_item(
    request: RemediationUpdateRequest, finding_data: Optional[FindingData] = None
) -> TransactWriteItem:
    timestamp = datetime.utcnow().isoformat() + "Z"
    sort_key = f"{request.finding_id}#{request.execution_id}"

    item = {
        "findingType": {"S": request.finding_type},
        "findingId": {"S": request.finding_id},
        FINDING_ID_EXECUTION_ID_KEY: {"S": sort_key},
        "executionId": {"S": request.execution_id},
        "remediationStatus": {"S": request.remediation_status},
        "lastUpdatedTime": {"S": timestamp},
        "lastUpdatedTime#findingId": {"S": f"{timestamp}#{request.finding_id}"},
        "REMEDIATION_CONSTANT": {"S": "remediation"},
        "lastUpdatedBy": {"S": request.lastUpdatedBy},
        "expireAt": {"N": str(calculate_history_ttl_timestamp(timestamp))},
        "accountId": {"S": request.account_id},
        "resourceId": {"S": request.resource_id},
        "resourceType": {"S": request.resource_type},
        "severity": {"S": request.severity},
        "region": {"S": request.region},
    }

    if request.error:
        item["error"] = {"S": request.error}

    if finding_data:
        _merge_finding_data_into_item(item, finding_data)

    history_create_item: TransactWriteItem = {
        "Put": {
            "TableName": HISTORY_TABLE_NAME,
            "Item": item,
            "ConditionExpression": "attribute_not_exists(findingType) AND attribute_not_exists(#sortKey)",
            "ExpressionAttributeNames": {
                SORT_KEY_ATTRIBUTE_NAME: FINDING_ID_EXECUTION_ID_KEY
            },
        }
    }

    return history_create_item


def _build_history_update_item(request: RemediationUpdateRequest) -> TransactWriteItem:
    update_expression = "SET remediationStatus = :rs"

    expression_values = {
        ":rs": {"S": request.remediation_status},
    }

    expression_names = {}

    if request.error:
        update_expression += ", #err = :err"
        expression_names["#err"] = "error"
        expression_values[":err"] = {"S": request.error}

    sort_key = f"{request.finding_id}#{request.execution_id}"

    history_update_item: TransactWriteItem = {
        "Update": {
            "TableName": HISTORY_TABLE_NAME,
            "Key": {
                "findingType": {"S": request.finding_type},
                FINDING_ID_EXECUTION_ID_KEY: {"S": sort_key},
            },
            "UpdateExpression": update_expression,
            "ExpressionAttributeValues": expression_values,
            "ConditionExpression": "attribute_exists(findingType) AND attribute_exists(#sortKey)",
        }
    }

    if expression_names:
        expression_names[SORT_KEY_ATTRIBUTE_NAME] = FINDING_ID_EXECUTION_ID_KEY
    else:
        expression_names = {SORT_KEY_ATTRIBUTE_NAME: FINDING_ID_EXECUTION_ID_KEY}

    history_update_item["Update"]["ExpressionAttributeNames"] = expression_names

    return history_update_item


def _extract_stepfunctions_execution_id(event: Event) -> str:
    execution_id = event.get("Notification", {}).get("StepFunctionsExecutionId")

    if not execution_id:
        logger.error("StepFunctionsExecutionId not found in event")
        return "unknown"

    return str(execution_id)


def _is_notified_workflow(event: Event) -> bool:
    if "Finding" not in event:
        return False

    finding = event["Finding"]
    workflow = finding.get("Workflow", {})

    if not isinstance(workflow, dict):
        return False

    workflow_status = workflow.get("Status", "")
    if workflow_status != "NOTIFIED":
        return False

    event_type = event.get("EventType", "")
    if event_type in (
        "Security Hub Findings - Custom Action",
        "Security Hub Findings - API Action",
    ):
        logger.debug(
            "NOTIFIED workflow detected but EventType indicates custom/API action - not skipping database updates",
            extra={"findingId": _extract_id(event), "eventType": event_type},
        )
        return False

    logger.debug(
        "NOTIFIED workflow detected - skipping database updates",
        extra={"findingId": _extract_id(event), "eventType": event_type},
    )
    return True


def get_control_id_from_finding_id(finding_id: str) -> Optional[str]:
    # Finding ID structure depends on consolidation settings
    # https://aws.amazon.com/blogs/security/consolidating-controls-in-security-hub-the-new-controls-view-and-consolidated-findings/

    # Unconsolidated finding ID pattern
    unconsolidated_pattern = r"^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:subscription\/(.+)\/finding\/.+$"
    unconsolidated_match = re.match(unconsolidated_pattern, finding_id)
    if unconsolidated_match:
        return unconsolidated_match.group(
            1
        )  # example: 'aws-foundational-security-best-practices/v/1.0.0/S3.1'

    # Consolidated finding ID pattern
    consolidated_pattern = r"^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:(.+)\/finding\/.+$"
    consolidated_match = re.match(consolidated_pattern, finding_id)
    if consolidated_match:
        return consolidated_match.group(1)  # example: 'security-control/Lambda.3'

    return None


def sanitize_control_id(control_id: str) -> str:
    non_alphanumeric_or_allowed = re.compile(r"[^a-zA-Z0-9/.-]")
    return non_alphanumeric_or_allowed.sub("", control_id)


def get_finding_type(event: Event) -> str:
    if "Finding" not in event:
        return ""

    finding_id = _extract_id(event)
    if finding_id:
        control_id_from_finding_id = get_control_id_from_finding_id(finding_id)
        if control_id_from_finding_id:
            return sanitize_control_id(control_id_from_finding_id)

    control_id = _extract_security_control_id(event)
    if control_id:
        return sanitize_control_id(control_id)

    return ""


def _extract_security_control_id(event: Event) -> str:
    if "Finding" not in event:
        return ""

    # Try to get SecurityControlId from Compliance first
    compliance = event["Finding"].get("Compliance", {})
    control_id = (
        compliance.get("SecurityControlId", "") if isinstance(compliance, dict) else ""
    )

    # If empty, fallback to ProductFields.ControlId
    if not control_id:
        product_fields = event["Finding"].get("ProductFields", {})
        control_id = (
            product_fields.get("ControlId", "")
            if isinstance(product_fields, dict)
            else ""
        )

    return str(control_id)


def _extract_id(event: Event) -> str:
    if "Finding" not in event:
        return ""

    finding_id = event["Finding"].get("Id", "")

    if not finding_id:
        product_fields = event["Finding"].get("ProductFields", {})
        finding_id = (
            product_fields.get("aws/securityhub/FindingId", "")
            if isinstance(product_fields, dict)
            else ""
        )

    return str(finding_id)


def _extract_resource_id(event: Event, resources: dict[str, Any]) -> str:
    resource_id = resources.get("Id", "") if resources else ""

    if not resource_id:
        product_fields = event.get("Finding", {}).get("ProductFields", {})
        if isinstance(product_fields, dict):
            resources_field = product_fields.get("Resources:0/Id", "")
            resource_id = str(resources_field) if resources_field else ""

    return resource_id


def _extract_finding_info(
    event: Event,
) -> tuple[Optional[sechub_findings.Finding], Union[str, FindingInfo]]:
    if "Finding" not in event:
        return None, ""

    finding = sechub_findings.Finding(event["Finding"])
    finding_info: FindingInfo = {
        "finding_id": finding.uuid or "",
        "finding_description": finding.description or "",
        "standard_name": finding.standard_name or "",
        "standard_version": finding.standard_version or "",
        "standard_control": finding.standard_control or "",
        "title": finding.title or "",
        "region": finding.region or "",
        "account": finding.account_id or "",
        "finding_arn": finding.arn or "",
    }
    return finding, finding_info


def _process_metrics(
    event: Event, status_from_event: str, control_id: str, custom_action_name: str
) -> None:
    metrics = Metrics()
    metrics_data = metrics.get_metrics_from_event(event)
    metrics_data["status"], metrics_data["status_reason"] = (
        Metrics.get_status_for_metrics(status_from_event)
    )
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

    if status_from_event in ("SUCCESS", "QUEUED"):
        notification.severity = "INFO"
    else:
        notification.severity = "ERROR"
        if finding:
            finding.flag(event["Notification"]["Message"])

    notification.send_to_sns = True
    return notification


# Check if Notification State is explicitly "NOT_NEW" and workflow status is "RESOLVED"
def _is_resolved_item(event: Event) -> bool:
    if "Finding" not in event:
        return False

    notification_state = event.get("Notification", {}).get("State", "")
    if notification_state != "NOT_NEW":
        return False

    finding = event["Finding"]
    workflow = finding.get("Workflow", {})

    if not isinstance(workflow, dict):
        return False

    workflow_status = workflow.get("Status", "")
    if workflow_status != "RESOLVED":
        return False

    return True


def _update_finding_remediation_status(
    execution_id: str,
    status_from_event: str,
    event: Event,
) -> None:
    remediation_status = map_remediation_status(status_from_event)
    error_message = None

    if remediation_status == "FAILED":
        error_message = event["Notification"].get("Details") or event[
            "Notification"
        ].get("Message", None)

    if _is_resolved_item(event):
        logger.warning(
            "Overriding remediation status to SUCCESS for resolved workflow with NOT_NEW state",
            extra={
                "findingId": _extract_id(event),
                "originalStatus": status_from_event,
                "overriddenStatus": "SUCCESS",
            },
        )
        remediation_status = "SUCCESS"
        error_message = None

    finding_id = _extract_id(event)
    finding_type = get_finding_type(event)

    logger.debug(
        "Finding processing",
        extra={
            "finding id": finding_id,
            "finding type": finding_type,
        },
    )

    try:
        resources = event.get("Resources", {})
        if isinstance(resources, list) and len(resources) > 0:
            resources = resources[0]
        elif not isinstance(resources, dict):
            resources = {}

        remediation_request = RemediationUpdateRequest(
            finding_id=finding_id,
            execution_id=execution_id,
            remediation_status=remediation_status,
            finding_type=finding_type,
            error=error_message,
            resource_id=_extract_resource_id(event, resources),
            resource_type=resources.get("Type", "") if resources else "",
            account_id=event.get("AccountId", ""),
            severity=(
                event.get("Severity", {}).get("Label", "")
                if event.get("Severity")
                else ""
            ),
            region=event.get("Region", ""),
            lastUpdatedBy="Automated",
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


def _parse_orchestrator_input(input_str: str) -> dict[str, Any]:
    try:
        result = json.loads(input_str)
        return cast(dict[str, Any], result)
    except (JSONDecodeError, TypeError) as e:
        logger.warning(
            "Failed to parse Step Functions input",
            extra={"input": input_str[:500], "error": str(e)},
        )
        return {}


def _add_optional_finding_fields(
    transformed_event: Event, finding_data: dict[str, Any]
) -> None:
    simple_field_mappings = {
        "AwsAccountId": "AccountId",
        "Region": "Region",
        "Resources": "Resources",
        "Severity": "Severity",
    }

    for source_field, target_field in simple_field_mappings.items():
        if source_field in finding_data:
            transformed_event[target_field] = finding_data[source_field]  # type: ignore[literal-required]

    # Handle nested ProductFields
    product_fields = finding_data.get("ProductFields", {})
    if isinstance(product_fields, dict) and "StandardsGuideArn" in product_fields:
        transformed_event["SecurityStandard"] = product_fields["StandardsGuideArn"]

    # Handle nested Compliance
    compliance = finding_data.get("Compliance", {})
    if isinstance(compliance, dict) and "SecurityControlId" in compliance:
        transformed_event["ControlId"] = compliance["SecurityControlId"]


def _transform_stepfunctions_failure_event(raw_event: dict[str, Any]) -> Event:
    try:
        detail = raw_event.get("detail", {})
        input_str = detail.get("input", "{}")
        orchestrator_input = _parse_orchestrator_input(input_str)

        findings_list = orchestrator_input.get("detail", {}).get("findings", [])
        finding_data = findings_list[0] if findings_list else {}

        finding_id = finding_data.get("Id", "unknown")
        execution_arn = detail.get("executionArn", "unknown")
        execution_name = detail.get("name", "unknown")
        status = detail.get("status", "FAILED")
        cause = detail.get("cause", status)
        error = detail.get("error", "")

        logger.info(
            "Transforming Step Functions failure event",
            extra={
                "findingId": finding_id,
                "executionArn": execution_arn,
                "executionName": execution_name,
                "status": status,
                "hasFindingData": bool(finding_data),
            },
        )

        error_details = (
            f"Error: {error}, Cause: {cause}" if error else f"Cause: {cause}"
        )

        transformed_event: Event = {
            "Notification": {
                "Message": f"Orchestrator execution {status.lower()}: {execution_arn}",
                "State": status,
                "Details": error_details,
                "StepFunctionsExecutionId": execution_arn,
            },
            "Finding": (
                finding_data
                if finding_data
                else {"Id": "unknown", "Title": "Step Functions Execution Failure"}
            ),
            "EventType": orchestrator_input.get(
                "detail-type", "Step Functions Failure"
            ),
        }

        # Add custom action name if present
        orchestrator_detail = orchestrator_input.get("detail", {})
        if "actionName" in orchestrator_detail:
            transformed_event["CustomActionName"] = orchestrator_detail["actionName"]

        # Add optional finding fields
        if finding_data:
            _add_optional_finding_fields(transformed_event, finding_data)

        return transformed_event
    except Exception as e:
        logger.error(
            "Critical error transforming Step Functions event",
            extra={"error": str(e), "rawEvent": str(raw_event)[:1000]},
            exc_info=True,
        )
        # Return a minimal valid event to prevent Lambda failure
        return {
            "Notification": {
                "Message": f"Failed to transform Step Functions event: {str(e)}",
                "State": "FAILED",
                "Details": str(raw_event)[:500],
                "StepFunctionsExecutionId": "unknown",
            },
            "Finding": {"Id": "unknown", "Title": "Transformation Error"},
            "EventType": "Error",
        }


@tracer.capture_lambda_handler  # type: ignore[misc]
def lambda_handler(event: Union[Event, dict[str, Any]], context: Any) -> None:
    try:
        # Type narrowing: check if this is a Step Functions event (raw dict)
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
            event = _transform_stepfunctions_failure_event(raw_event)
    except Exception as e:
        logger.error(
            "Failed to transform event - continuing with original",
            extra={"error": str(e)},
            exc_info=True,
        )
        # Don't raise - try to process with original event structure

    # Type assertion: at this point, event should be of type Event
    event = cast(Event, event)

    message_prefix, message_suffix = set_message_prefix_and_suffix(event)
    stepfunctions_execution_id = _extract_stepfunctions_execution_id(event)
    status_from_event = event.get("Notification", {}).get("State", "").upper()

    finding, finding_info = _extract_finding_info(event)

    control_id = _extract_security_control_id(event)
    custom_action_name = event.get("CustomActionName", "")

    _process_metrics(event, status_from_event, control_id, custom_action_name)

    notification = _create_notification(
        event, status_from_event, stepfunctions_execution_id, finding
    )

    build_and_send_notification(
        event, notification, message_prefix, message_suffix, finding_info
    )

    is_notified_workflow = _is_notified_workflow(event)

    if "Finding" in event and not is_notified_workflow:
        _update_finding_remediation_status(
            stepfunctions_execution_id, status_from_event, event
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

    notification.remediation_output = event["Notification"].get("RemediationOutput", "")

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
    except Exception as e:
        logger.debug(f"Encountered error sending Cloudwatch metric: {str(e)}")
