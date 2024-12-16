# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from json.decoder import JSONDecodeError
from typing import Any, NotRequired, TypedDict, Union

from aws_lambda_powertools.utilities.typing import LambdaContext
from layer import sechub_findings, tracer_utils
from layer.cloudwatch_metrics import CloudWatchMetrics
from layer.logger import Logger
from layer.metrics import Metrics
from layer.utils import get_account_alias

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv(
    "AWS_DEFAULT_REGION", "us-east-1"
)  # MUST BE SET in global variables
AWS_PARTITION = os.getenv("AWS_PARTITION", "aws")  # MUST BE SET in global variables
WEB_PARTITION = {
    "aws-cn": "amazonaws.cn",
    "aws-us-gov": "amazonaws-us-gov",
    "aws": "aws.amazon",
}

# initialise loggers
LOG_LEVEL = os.getenv("log_level", "info")
LOGGER = Logger(loglevel=LOG_LEVEL)

tracer = tracer_utils.init_tracer()


def format_details_for_output(details):
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
    message_prefix = event["Notification"].get("ExecId", "")
    message_suffix = event["Notification"].get("AffectedObject", "")
    if message_prefix:
        message_prefix += ": "
    if message_suffix:
        message_suffix = f" ({message_suffix})"
    return message_prefix, message_suffix


class Notification(TypedDict):
    Message: str
    State: str
    Details: NotRequired[str]
    RemediationOutput: NotRequired[str]


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


# powertools tracer decorator is not typed
@tracer.capture_lambda_handler  # type: ignore[misc]
def lambda_handler(event: Event, _: LambdaContext) -> None:
    message_prefix, message_suffix = set_message_prefix_and_suffix(event)

    # Get finding status
    finding_status = "FAILED"  # default state
    if event["Notification"]["State"].upper() == "SUCCESS":
        finding_status = "RESOLVED"
    elif event["Notification"]["State"].upper() == "QUEUED":
        finding_status = "PENDING"

    finding = None
    finding_info: Union[str, dict[str, Any]] = ""
    if "Finding" in event:
        finding = sechub_findings.Finding(event["Finding"])
        finding_info = {
            "finding_id": finding.uuid,
            "finding_description": finding.description,
            "standard_name": finding.standard_name,
            "standard_version": finding.standard_version,
            "standard_control": finding.standard_control,
            "title": finding.title,
            "region": finding.region,
            "account": finding.account_id,
            "finding_arn": finding.arn,
        }

    event_state = event["Notification"]["State"].upper()

    control_id = (
        event["Finding"].get("Compliance", {}).get("SecurityControlId", "")
        if "Finding" in event
        else ""
    )
    custom_action_name = (
        event["CustomActionName"] if "CustomActionName" in event else ""
    )

    # Send anonymous metrics
    if "EventType" in event:
        metrics = Metrics(event["EventType"])
        metrics_data = metrics.get_metrics_from_event(event)
        metrics_data["status"] = finding_status
        metrics.send_metrics(metrics_data)

        create_and_send_cloudwatch_metrics(event_state, control_id, custom_action_name)

    if event_state in ("SUCCESS", "QUEUED"):
        notification = sechub_findings.SHARRNotification(
            event.get("SecurityStandard", "SHARR"),
            AWS_REGION,
            event.get("ControlId", None),
        )
        notification.severity = "INFO"
        notification.send_to_sns = True

    elif event_state == "FAILED":
        notification = sechub_findings.SHARRNotification(
            event.get("SecurityStandard", "SHARR"),
            AWS_REGION,
            event.get("ControlId", None),
        )
        notification.severity = "ERROR"
        notification.send_to_sns = True

    elif event_state in {"WRONGSTANDARD", "LAMBDAERROR"}:
        notification = sechub_findings.SHARRNotification("SHARR", AWS_REGION, None)
        notification.severity = "ERROR"
        notification.send_to_sns = True
    else:
        notification = sechub_findings.SHARRNotification(
            event.get("SecurityStandard", "SHARR"),
            AWS_REGION,
            event.get("ControlId", None),
        )
        notification.severity = "ERROR"
        if finding:
            finding.flag(event["Notification"]["Message"])
        notification.send_to_sns = True
    build_and_send_notification(
        event, notification, message_prefix, message_suffix, control_id, finding_info
    )


def build_and_send_notification(
    event: Event,
    notification: sechub_findings.SHARRNotification,
    message_prefix: str,
    message_suffix: str,
    control_id: str,
    finding_info: Union[str, dict[str, Any]],
) -> None:
    notification.message = (
        message_prefix + event["Notification"]["Message"] + message_suffix
    )

    notification.remediation_output = event["Notification"].get("RemediationOutput", "")

    notification.finding_link = (
        f"https://{AWS_REGION}.console.{WEB_PARTITION[AWS_PARTITION]}.com/securityhub/home"
        f"?region={AWS_REGION}#/controls/{control_id}"
    )

    notification.remediation_status = event["Notification"]["State"].upper()

    remediation_account_id = ""
    if isinstance(finding_info, dict):
        remediation_account_id = (
            finding_info["account"] if "account" in finding_info else ""
        )

    notification.remediation_account_alias = get_account_alias(remediation_account_id)

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

    notification.finding_info = finding_info
    notification.notify()


def create_and_send_cloudwatch_metrics(
    event_state: str, control_id: str, custom_action_name: Union[None, str]
) -> None:
    try:
        cloudwatch_metrics = CloudWatchMetrics()
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
        LOGGER.debug(f"Encountered error sending Cloudwatch metric: {str(e)}")
