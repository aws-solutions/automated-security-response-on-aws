# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from json.decoder import JSONDecodeError
import boto3
import os
import sechub_findings
from logger import Logger
from metrics import Metrics

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')   # MUST BE SET in global variables
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')           # MUST BE SET in global variables

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)

def format_details_for_output(details):
    """Handle various possible formats in the details"""
    details_formatted = []
    if isinstance(details, list):
        details_formatted = details
    elif isinstance(details, str) and details[0:6] == "Cause:":
        try:
            details_formatted = json.dumps(json.loads(details[7:]), indent=2).split('\n')
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
    message_prefix = event['Notification'].get('ExecId','')
    message_suffix = event['Notification'].get('AffectedObject', '')
    if message_prefix:
        message_prefix += ': '
    if message_suffix:
        message_suffix = f' ({message_suffix})'
    return message_prefix, message_suffix

def lambda_handler(event, _):
    # Expected input:
    # Notification:
    #   Message: string
    #   State: string
    #   Details?: string
    #   updateSecHub: yes|NO
    # Payload: contains the Step Function Input to the previous state and consists of:
    #   Finding?: json
    #   ControlId?: string
    #   SecurityStandard?: string
    #   EventType?: string

    message_prefix, message_suffix = set_message_prefix_and_suffix(event)

    # Get finding status
    finding_status = 'FAILED' # default state
    if event['Notification']['State'].upper == 'SUCCESS':
        finding_status = 'RESOLVED'
    elif event['Notification']['State'].upper == 'QUEUED':
        finding_status = 'PENDING'
    # elif event['Notification']['State'].upper == 'FAILED':
    #     finding_status = 'FAILED'

    finding = None
    finding_info = ''
    if 'Finding' in event:
        finding = sechub_findings.Finding(event['Finding'])
        finding_info = {
            'finding_id': finding.uuid,
            'finding_description': finding.description,
            'standard_name': finding.standard_name,
            'standard_version': finding.standard_version,
            'standard_control': finding.standard_control,
            'title': finding.title,
            'region': finding.region,
            'account': finding.account_id,
            'finding_arn': finding.arn
        }

    # Send anonymous metrics
    if 'EventType' in event and 'Finding' in event:
        metrics = Metrics(event['EventType'])
        metrics_data = metrics.get_metrics_from_finding(event['Finding'])
        metrics_data['status'] = finding_status
        metrics.send_metrics(metrics_data)

    if event['Notification']['State'].upper() in ('SUCCESS', 'QUEUED'):
        notification = sechub_findings.SHARRNotification(
            event.get('SecurityStandard', 'SHARR'),
            AWS_REGION,
            event.get('ControlId', None)
        )
        notification.severity = 'INFO'
        notification.send_to_sns = True

    elif event['Notification']['State'].upper() == 'FAILED':
        notification = sechub_findings.SHARRNotification(
            event.get('SecurityStandard', 'SHARR'),
            AWS_REGION,
            event.get('ControlId', None)
        )
        notification.severity = 'ERROR'
        notification.send_to_sns = True

    elif event['Notification']['State'].upper() in {'WRONGSTANDARD', 'LAMBDAERROR'}:
        notification = sechub_findings.SHARRNotification('SHARR',AWS_REGION, None)
        notification.severity = 'ERROR'

    else:
        notification = sechub_findings.SHARRNotification(
            event.get('SecurityStandard', 'SHARR'),
            AWS_REGION,
            event.get('ControlId', None)
        )
        notification.severity = 'ERROR'
        if finding:
            finding.flag(event['Notification']['Message'])

    notification.message = message_prefix + event['Notification']['Message'] + message_suffix
    if 'Details' in event['Notification'] and event['Notification']['Details'] != 'MISSING':
        notification.logdata = format_details_for_output(event['Notification']['Details'])

    notification.finding_info = finding_info
    notification.notify()
