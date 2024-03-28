# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from layer.cloudwatch_metrics import CloudWatchMetrics
from layer.logger import Logger

# initialise loggers
LOG_LEVEL = os.getenv("log_level", "info")
LOGGER = Logger(loglevel=LOG_LEVEL)

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_dynamodb():
    return boto3.client("dynamodb", config=boto_config)


def connect_to_sfn():
    return boto3.client("stepfunctions", config=boto_config)


def lambda_handler(event, _):
    """
    Schedules a remediation for execution.

    `event` should have the following keys and values:
    `Records`: Contains the items that are sent from SQS:
        `body`: Contains a JSON string that has:
            `ResourceRegion`: The region that the remediation will be run in.
            `AccountId`: The account that the remediation will be run on.
            `TaskToken`: The task token sent by the Orchestrator to determine whether this execution has completed successfully.
            `RemediationDetails`: Details for the remediation that are needed for the next step.

    `context` is ignored
    """
    try:
        record = event["Records"][0]
        body = json.loads(record["body"])
        region = body["ResourceRegion"]
        account_id = body["AccountId"]
        task_token = body["TaskToken"]
        remediation_details = body["RemediationDetails"]
        table_key = f"{account_id}-{region}"
        table_name = get_table_name()
        wait_threshold = get_wait_threshold()
        current_timestamp = int(datetime.now(timezone.utc).timestamp())

        dynamodb_client = connect_to_dynamodb()
        sfn_client = connect_to_sfn()

        result = dynamodb_client.get_item(
            TableName=table_name, Key={"AccountID-Region": {"S": table_key}}
        )

        if "Item" in result and "LastExecutedTimestamp" in result["Item"]:
            found_timestamp_string = result["Item"]["LastExecutedTimestamp"]["S"]
            found_timestamp = int(found_timestamp_string)

            new_timestamp = (
                found_timestamp + wait_threshold
                if found_time_is_within_wait_threshold(found_timestamp)
                else current_timestamp
            )
            new_timestamp_ttl = new_timestamp + wait_threshold

            dynamodb_client.put_item(
                TableName=table_name,
                Item={
                    "AccountID-Region": {"S": table_key},
                    "LastExecutedTimestamp": {"S": str(new_timestamp)},
                    "TTL": {"N": str(new_timestamp_ttl)},
                },
                ConditionExpression="LastExecutedTimestamp = :timestamp",
                ExpressionAttributeValues={":timestamp": {"S": found_timestamp_string}},
            )
            create_and_send_metric(new_timestamp, current_timestamp)
            return send_success_to_step_function(
                sfn_client, task_token, new_timestamp, remediation_details
            )
        else:
            put_initial_in_dynamodb(table_name, table_key, current_timestamp)
            create_and_send_metric(current_timestamp, current_timestamp)
            return send_success_to_step_function(
                sfn_client,
                task_token,
                current_timestamp,
                remediation_details,
            )
    except Exception as e:
        sfn_client = connect_to_sfn()
        sfn_client.send_task_failure(
            taskToken=task_token,
            error=e.__class__.__name__,
            cause=str(e),
        )


def get_wait_threshold() -> int:
    wait_threshold_string = os.environ.get("RemediationWaitTime")
    if wait_threshold_string is None:
        raise ValueError("Cannot proceed without wait threshold set")
    return int(wait_threshold_string)


def get_table_name() -> str:
    table_name = os.environ.get("SchedulingTableName")
    if table_name is None:
        raise ValueError("Cannot proceed without table name set")
    return table_name


def found_time_is_within_wait_threshold(found_time: int) -> bool:
    return (
        int(datetime.now(timezone.utc).timestamp()) - found_time <= get_wait_threshold()
    )


def put_initial_in_dynamodb(
    table_name: str, table_key: str, current_timestamp: int
) -> None:
    dynamodb_client = connect_to_dynamodb()
    wait_threshold = get_wait_threshold()
    current_timestamp_ttl = current_timestamp + wait_threshold

    dynamodb_client.put_item(
        TableName=table_name,
        Item={
            "AccountID-Region": {"S": table_key},
            "LastExecutedTimestamp": {"S": str(current_timestamp)},
            "TTL": {"N": str(current_timestamp_ttl)},
        },
    )


def send_success_to_step_function(
    sfn_client, task_token, new_timestamp, remediation_details
):
    # Formatting for expected State Machine time
    planned_timestamp = datetime.fromtimestamp(new_timestamp, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    output_dict = {"PlannedTimestamp": planned_timestamp}
    output_dict.update(remediation_details)

    sfn_client.send_task_success(
        taskToken=task_token,
        output=json.dumps(output_dict),
    )
    return f"Remediation scheduled to execute at {planned_timestamp}"


def create_and_send_metric(new_timestamp, current_timestamp):
    try:
        cloudwatch_metrics = CloudWatchMetrics()
        cloudwatch_metric = {
            "MetricName": "RemediationSchedulingDelay",
            "Unit": "Seconds",
            "Value": new_timestamp - current_timestamp,
        }
        cloudwatch_metrics.send_metric(cloudwatch_metric)
    except Exception:
        LOGGER.debug("Did not send Cloudwatch metric")
