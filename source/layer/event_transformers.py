# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import re
from json.decoder import JSONDecodeError
from typing import Any, NotRequired, TypedDict, Union, cast

from layer.powertools_logger import get_logger
from layer.sechub_findings import extract_finding_id

logger = get_logger("event_transformers")


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
    SSMExecution: NotRequired[dict[str, Any]]


def extract_stepfunctions_execution_id(event: Event) -> str:
    execution_id = event.get("Notification", {}).get("StepFunctionsExecutionId")

    if not execution_id:
        logger.error("StepFunctionsExecutionId not found in event")
        return "unknown"

    return str(execution_id)


def is_notified_workflow(event: Event) -> bool:
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
    event_dict = cast(dict[str, Any], cast(object, event))
    if event_type in (
        "Security Hub Findings - Custom Action",
        "Security Hub Findings - API Action",
    ):
        logger.debug(
            "NOTIFIED workflow detected but EventType indicates custom/API action - not skipping database updates",
            extra={
                "findingId": extract_finding_id(event_dict),
                "eventType": event_type,
            },
        )
        return False

    logger.debug(
        "NOTIFIED workflow detected - skipping database updates",
        extra={"findingId": extract_finding_id(event_dict), "eventType": event_type},
    )
    return True


def is_resolved_item(event: Event) -> bool:
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


def parse_orchestrator_input(input_str: str) -> dict[str, Any]:
    try:
        result = json.loads(input_str)
        return cast(dict[str, Any], result)
    except (JSONDecodeError, TypeError) as e:
        logger.warning(
            "Failed to parse Step Functions input",
            extra={"input": input_str[:500], "error": str(e)},
        )
        return {}


def extract_account_id(event: Event) -> str:
    """Extract account ID from event with fallback to nested locations.

    Tries to extract from Orchestrator "Notify" step payload structure first (event.AccountId),
    then falls back to "Queued Notification" step payload structure (event.Finding.AwsAccountId,
    event.SSMExecution.Account).
    """
    return (
        event.get("AccountId", "")
        or event.get("Finding", {}).get("AwsAccountId", "")
        or event.get("SSMExecution", {}).get("Account", "")
    )


_ACCESS_ANALYZER_FINDING_ID_PREFIX = re.compile(
    r"^arn:(?:aws|aws-cn|aws-us-gov):access-analyzer:"
)

# Matches a 12-digit AWS account id.
_AWS_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")


def _is_access_analyzer_finding(event: Event) -> bool:
    """True when the finding is an IAM Access Analyzer finding.

    Identified by the native access-analyzer ARN used as the finding id — the
    same signal the backend uses (getControlIdFromFindingId maps this prefix to
    IAMAccessAnalyzer.ExternalAccess). Only these findings carry the resource
    owner in ProductFields.ResourceOwnerAccount.
    """
    finding = event.get("Finding", {})
    if not isinstance(finding, dict):
        return False
    finding_id = finding.get("Id", "")
    return isinstance(finding_id, str) and bool(
        _ACCESS_ANALYZER_FINDING_ID_PREFIX.match(finding_id)
    )


def extract_resource_owner_account(event: Event) -> str:
    """Extract ProductFields.ResourceOwnerAccount from the finding, if present.

    IAM Access Analyzer organization-analyzer findings set
    ProductFields.ResourceOwnerAccount to the account that owns the resource,
    which differs from AwsAccountId (the administrator account). The field is
    IAM Access Analyzer-specific, so its presence identifies such a finding.
    Returns "" when the finding, ProductFields, or the field is absent.
    """
    finding = event.get("Finding", {})
    if not isinstance(finding, dict):
        return ""
    product_fields = finding.get("ProductFields", {})
    if not isinstance(product_fields, dict):
        return ""
    return str(product_fields.get("ResourceOwnerAccount", "") or "")


def resolve_finding_account_id(event: Event) -> str:
    """Resolve the account that owns the resource a finding reports on.

    For IAM Access Analyzer organization-analyzer findings, ASFF AwsAccountId is
    the administrator account while the resource lives in the account named by
    ProductFields.ResourceOwnerAccount, so that field is preferred — but only
    for Access Analyzer findings, matching the backend
    FindingDataService.resolveAccountId. Every other finding (and Access
    Analyzer findings without the field) uses extract_account_id, so findings
    that merely happen to carry ResourceOwnerAccount are unaffected.
    """
    if _is_access_analyzer_finding(event):
        resource_owner_account = extract_resource_owner_account(event)
        # Only trust ResourceOwnerAccount when it is a 12-digit account id: it is
        # a free-form ProductFields entry that becomes the accountId used for
        # account-scoped authorization, so a malformed/crafted value must not be
        # used. Fall back to AwsAccountId otherwise (matching the runbook parse
        # script's ^\d{12}$ check).
        if _AWS_ACCOUNT_ID_PATTERN.match(resource_owner_account):
            return resource_owner_account
        if resource_owner_account:
            logger.warning(
                "Ignoring malformed ResourceOwnerAccount on Access Analyzer finding; falling back to AwsAccountId",
                extra={
                    "findingId": extract_finding_id(cast(dict[str, Any], event)),
                    "resourceOwnerAccount": resource_owner_account,
                },
            )
    return extract_account_id(event)


def extract_region(event: Event) -> str:
    """Extract region from event with fallback to nested locations.

    Tries to extract from Orchestrator "Notify" step payload structure first (event.Region),
    then falls back to "Queued Notification" step payload structure (event.Finding.Region,
    event.SSMExecution.Region).
    """
    return (
        event.get("Region", "")
        or event.get("Finding", {}).get("Region", "")
        or event.get("SSMExecution", {}).get("Region", "")
    )


def extract_severity(event: Event) -> str:
    """Extract severity label from event with fallback to nested locations.

    Tries to extract from Orchestrator "Notify" step payload structure first (event.Severity.Label),
    then falls back to "Queued Notification" step payload structure (event.Finding.Severity.Label).
    """
    severity = event.get("Severity", {}).get("Label", "")
    if not severity:
        severity = event.get("Finding", {}).get("Severity", {}).get("Label", "")
    return str(
        severity
    )  # cast to str to avoid type error due to Severity being dict[str,Any]


def extract_resources(event: Event) -> dict[str, Any]:
    """Extract first resource from event with fallback to nested locations.

    Tries to extract from Orchestrator "Notify" step payload structure first (event.Resources),
    then falls back to "Queued Notification" step payload structure (event.Finding.Resources).
    Returns the first resource as a dict, or empty dict if no resources found.
    """
    resources = event.get("Resources") or event.get("Finding", {}).get("Resources", [])

    if isinstance(resources, dict):
        return resources
    if isinstance(resources, list) and resources:
        return resources[0]
    return {}


def add_optional_finding_fields(
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


def transform_stepfunctions_failure_event(raw_event: dict[str, Any]) -> Event:
    try:
        detail = raw_event.get("detail", {})
        input_str = detail.get("input", "{}")
        orchestrator_input = parse_orchestrator_input(input_str)

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
            add_optional_finding_fields(transformed_event, finding_data)

        return transformed_event
    except Exception as e:
        logger.error(
            "Critical error transforming Step Functions event",
            extra={"error": str(e), "rawEvent": str(raw_event)[:1000]},
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
