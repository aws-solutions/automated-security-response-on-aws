# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


class LogGroupOperationError(Exception):
    pass


class LogGroupNotFoundError(LogGroupOperationError):
    pass


def connect_to_logs(boto_config):
    return boto3.client("logs", config=boto_config)


def sleep_between_attempts():
    time.sleep(2)


def _find_existing_log_group(cwl_client, log_group_name):
    try:
        describe_group = cwl_client.describe_log_groups(
            logGroupNamePrefix=log_group_name
        )
        for group in describe_group["logGroups"]:
            if group["logGroupName"] == log_group_name:
                print(
                    f"Log group '{log_group_name}' already exists with ARN: {group['arn']}"
                )
                return str(group["arn"])
    except ClientError as err:
        print(f"Error checking for existing log groups: {str(err)}")
    return None


def _create_log_group(cwl_client, log_group_name):
    try:
        print(f"Attempting to create log group '{log_group_name}'...")
        cwl_client.create_log_group(logGroupName=log_group_name)
        print(f"Successfully created log group '{log_group_name}'")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceAlreadyExistsException":
            print(
                f"Log group '{log_group_name}' was created by another process, continuing..."
            )
        else:
            print(f"Error creating log group: {error_code} - {str(e)}")
            raise e
    except Exception as e:
        print(f"Unexpected error creating log group: {str(e)}")
        raise LogGroupOperationError(
            f"Failed to create log group {log_group_name}: {str(e)}"
        ) from e


def _wait_for_log_group_creation(cwl_client, log_group_name, max_retries=3):
    attempts = 0
    while attempts < max_retries:
        try:
            describe_group = cwl_client.describe_log_groups(
                logGroupNamePrefix=log_group_name
            )
            print(f"Found {len(describe_group['logGroups'])} log groups")
            for group in describe_group["logGroups"]:
                if group["logGroupName"] == log_group_name:
                    return str(group["arn"])

            # Log group not found yet, wait and retry
            sleep_between_attempts()
            attempts += 1

        except ClientError as err:
            print(f"Error describing log groups: {str(err)}")
            if attempts >= max_retries - 1:
                raise LogGroupNotFoundError(
                    f"Failed to find Log Group {log_group_name}: {str(err)}"
                )
            sleep_between_attempts()
            attempts += 1

    raise LogGroupNotFoundError(
        f"Failed to find Log Group {log_group_name}: Timed out after {max_retries} attempts"
    )


def create_or_get_loggroup(event, _):
    boto_config = Config(retries={"mode": "standard"})
    cwl_client = connect_to_logs(boto_config)
    log_group_name = event["LogGroup"]

    existing_arn = _find_existing_log_group(cwl_client, log_group_name)
    if existing_arn:
        return existing_arn

    _create_log_group(cwl_client, log_group_name)

    return _wait_for_log_group_creation(cwl_client, log_group_name)


# Keep the old function for backward compatibility
def wait_for_loggroup(event, _):
    return create_or_get_loggroup(event, _)
