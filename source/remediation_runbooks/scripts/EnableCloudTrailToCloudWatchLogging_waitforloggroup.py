# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import time

import boto3
from botocore.config import Config


def connect_to_logs(boto_config):
    return boto3.client("logs", config=boto_config)


def sleep_between_attempts():
    time.sleep(2)


def wait_for_loggroup(event, _):
    boto_config = Config(retries={"mode": "standard"})
    cwl_client = connect_to_logs(boto_config)

    max_retries = 3
    attempts = 0
    while attempts < max_retries:
        try:
            describe_group = cwl_client.describe_log_groups(
                logGroupNamePrefix=event["LogGroup"]
            )
            print(len(describe_group["logGroups"]))
            for group in describe_group["logGroups"]:
                if group["logGroupName"] == event["LogGroup"]:
                    return str(group["arn"])
            # no match - wait and retry
            sleep_between_attempts()
            attempts += 1

        except Exception as err:
            exit(f'Failed to create Log Group {event["LogGroup"]}: {str(err)}')

    exit(f'Failed to create Log Group {event["LogGroup"]}: Timed out')
