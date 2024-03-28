# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from json.decoder import JSONDecodeError
from typing import Any, Union

from layer import sechub_findings
from layer.cloudwatch_metrics import CloudWatchMetrics
from layer.logger import Logger
from layer.metrics import Metrics

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv(
    "AWS_DEFAULT_REGION", "us-east-1"
)  # MUST BE SET in global variables
AWS_PARTITION = os.getenv("AWS_PARTITION", "aws")  # MUST BE SET in global variables

# initialise loggers
LOG_LEVEL = os.getenv("log_level", "info")
LOGGER = Logger(loglevel=LOG_LEVEL)


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


def lambda_handler(event, _):
    # Expected input:
    # Notification:
    #   Message: string
    #   State: string
    #   Details?: string
    # Finding?: json
    # EventType?: string
    # AutomationDocument:
    #   ControlId?: string
    #   SecurityStandard?: string

    message_prefix, message_suffix = set_message_prefix_and_suffix(event)

    # Get finding status
    finding_status = "FAILED"  # default state
    if event["Notification"]["State"].upper == "SUCCESS":
        finding_status = "RESOLVED"
    elif event["Notification"]["State"].upper == "QUEUED":
        finding_status = "PENDING"
    # elif event['Notification']['State'].upper == 'FAILED':
    #     finding_status = 'FAILED'

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

    # Send anonymous metrics
    if "EventType" in event and "Finding" in event:
        metrics = Metrics(event["EventType"])
        metrics_data = metrics.get_metrics_from_finding(event["Finding"])
        metrics_data["status"] = finding_status
        metrics.send_metrics(metrics_data)

        create_and_send_cloudwatch_metric(event_state)

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

    else:
        notification = sechub_findings.SHARRNotification(
            event.get("SecurityStandard", "SHARR"),
            AWS_REGION,
            event.get("ControlId", None),
        )
        notification.severity = "ERROR"
        if finding:
            finding.flag(event["Notification"]["Message"])

    notification.message = (
        message_prefix + event["Notification"]["Message"] + message_suffix
    )
    if (
        "Details" in event["Notification"]
        and event["Notification"]["Details"] != "MISSING"
    ):
        notification.logdata = format_details_for_output(
            event["Notification"]["Details"]
        )

    notification.finding_info = finding_info
    notification.notify()


def create_and_send_cloudwatch_metric(event_state):
    try:
        cloudwatch_metrics = CloudWatchMetrics()
        cloudwatch_metric = {
            "MetricName": "RemediationOutcome",
            "Dimensions": [
                {
                    "Name": "Outcome",
                    "Value": event_state,
                },
            ],
            "Unit": "Count",
            "Value": 1,
        }
        cloudwatch_metrics.send_metric(cloudwatch_metric)
    except Exception:
        LOGGER.debug("Did not send Cloudwatch metric")
