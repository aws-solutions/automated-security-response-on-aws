# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def connect_to_logs(boto_config):
    return boto3.client("logs", config=boto_config)


def connect_to_ec2(boto_config):
    return boto3.client("ec2", config=boto_config)


def log_group_exists(client, group):
    try:
        log_group_verification = client.describe_log_groups(logGroupNamePrefix=group)[
            "logGroups"
        ]
        if len(log_group_verification) >= 1:
            for existing_loggroup in log_group_verification:
                if existing_loggroup["logGroupName"] == group:
                    return 1
        return 0

    except Exception as e:
        exit(f"EnableVPCFlowLogs failed - unhandled exception {str(e)}")


def wait_for_seconds(wait_interval):
    time.sleep(wait_interval)


def wait_for_loggroup(client, wait_interval, max_retries, loggroup):
    attempts = 1
    while not log_group_exists(client, loggroup):
        wait_for_seconds(wait_interval)
        attempts += 1
        if attempts > max_retries:
            exit(f"Timeout waiting for log group {loggroup} to become active")


def flowlogs_active(client, loggroup):
    # searches for flow log status, filtered on unique CW Log Group created earlier
    try:
        flow_status = client.describe_flow_logs(
            DryRun=False,
            Filters=[
                {"Name": "log-group-name", "Values": [loggroup]},
            ],
        )["FlowLogs"]
        if len(flow_status) == 1 and flow_status[0]["FlowLogStatus"] == "ACTIVE":
            return 1
        else:
            return 0

    except Exception as e:
        exit(f"EnableVPCFlowLogs failed - unhandled exception {str(e)}")


def wait_for_flowlogs(client, wait_interval, max_retries, loggroup):
    attempts = 1
    while not flowlogs_active(client, loggroup):
        wait_for_seconds(wait_interval)
        attempts += 1
        if attempts > max_retries:
            exit(
                f"Timeout waiting for flowlogs to log group {loggroup} to become active"
            )


def enable_flow_logs(event, _):
    """
    remediates CloudTrail.2 by enabling SSE-KMS
    On success returns a string map
    On failure returns NoneType
    """
    max_retries = event.get(
        "retries", 12
    )  # max number of waits for actions to complete.
    wait_interval = event.get("wait", 5)  # how many seconds between attempts

    boto_config = Config(retries={"mode": "standard"})

    if (
        "vpc" not in event
        or "remediation_role" not in event
        or "kms_key_arn" not in event
    ):
        exit("Error: missing vpc from input")

    logs_client = connect_to_logs(boto_config)
    ec2_client = connect_to_ec2(boto_config)

    kms_key_arn = event["kms_key_arn"]  # for logs encryption at rest

    # set dynamic variable for CW Log Group for VPC Flow Logs
    vpc_flow_loggroup = "VPCFlowLogs/" + event["vpc"]
    # create cloudwatch log group
    try:
        logs_client.create_log_group(
            logGroupName=vpc_flow_loggroup, kmsKeyId=kms_key_arn
        )
    except ClientError as client_error:
        exception_type = client_error.response["Error"]["Code"]

        if exception_type in ["ResourceAlreadyExistsException"]:
            print(f"CloudWatch Logs group {vpc_flow_loggroup} already exists")
        else:
            exit(f"ERROR CREATING LOGGROUP {vpc_flow_loggroup}: {str(exception_type)}")

    except Exception as e:
        exit(f"ERROR CREATING LOGGROUP {vpc_flow_loggroup}: {str(e)}")

    # wait for CWL creation to propagate
    wait_for_loggroup(logs_client, wait_interval, max_retries, vpc_flow_loggroup)

    # create VPC Flow Logging
    try:
        ec2_client.create_flow_logs(
            DryRun=False,
            DeliverLogsPermissionArn=event["remediation_role"],
            LogGroupName=vpc_flow_loggroup,
            ResourceIds=[event["vpc"]],
            ResourceType="VPC",
            TrafficType="REJECT",
            LogDestinationType="cloud-watch-logs",
        )
    except ClientError as client_error:
        exception_type = client_error.response["Error"]["Code"]

        if exception_type in ["FlowLogAlreadyExists"]:
            return {
                "response": {
                    "message": f'VPC Flow Logs for {event["vpc"]} already enabled',
                    "status": "Success",
                }
            }
        else:
            exit(f"ERROR CREATING LOGGROUP {vpc_flow_loggroup}: {str(exception_type)}")
    except Exception as e:
        exit(f"create_flow_logs failed {str(e)}")

    # wait for Flow Log creation to propagate. Exits on timeout (no need to check results)
    wait_for_flowlogs(ec2_client, wait_interval, max_retries, vpc_flow_loggroup)

    # wait_for_flowlogs will exit if unsuccessful after max_retries * wait_interval (60 seconds by default)
    return {
        "response": {
            "message": f'VPC Flow Logs enabled for {event["vpc"]} to {vpc_flow_loggroup}',
            "status": "Success",
        }
    }
