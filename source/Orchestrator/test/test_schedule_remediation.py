# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit Test: schedule_remediation.py
Run from /deployment/temp/source/Orchestrator after running build-s3-dist.sh
"""
import json
import os
from datetime import datetime, timezone
from unittest.mock import patch

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws
from schedule_remediation import lambda_handler

os.environ["SchedulingTableName"] = "TestTable"
os.environ["RemediationWaitTime"] = "3"
timestampFormat = "%Y-%m-%dT%H:%M:%SZ"

client = "boto3.client"

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})

event = {
    "Records": [
        {
            "messageId": "21dbdb16-cc07-404c-ae56-32b619200719",
            "receiptHandle": "AQEB4Pirw/FVegbE1FRgLIUxac/EI2ihP+i/FVEp2bUE8PSbAKD3B3NZLXgJwIcjb73qa3OtT2mJ4jolFR7suHSQbSMdXR06axd66tpllyV+eAsSwlAihQuk56iZbBrW/nDFpES/Eb3K4AYssUtG3Uf++abdt2b4lPzImS4XW5GIuEQmYU4e22QhgDEhp0GC4Np5JigJeTFvWD9yuljgWOhlVAixmT7oy0GZwVrPchcgBN5pcoRwlRNHI6TmX8/FnEvv1UwC7KvhfywmWEGxx4TAGmO5aZu4ZKLXKIb0QiJXqRpwZV2yCRSayrV91DXqnyzTve7tUrX1Dp8yfA9AFxvNMMFgx3MxnRSKrusKzDjWI1BI6P/Y/99VXzTtPlYFfXqJgwiHEjMnIgSqdHvN8CYFMlZtsw0rbMRPnQzzIzhW6SQqAuDWfNrwy47Q8w8vcVri",
            "body": '{"ResourceRegion":"us-east-1","executionId":"arn:aws:states:us-east-1:111111111:execution:SO0111-SHARR-Orchestrator:b24425f3-d43c-6ba7-c977-8fcbbc819025_24b1b193-c9cb-dfa0-2d3b-e1a8f4479dcc","AccountId":"111111111","RemediationDetails":{"Test":"Test"},"TaskToken":"AQCEAAAAKgAAAAMAAAAAAAAAAY9E4q9gMWM6RtheL2A6dR2HfHYkPARJ/WNksPpfUbAliiuAGWorrgnlcIfDhUbTHyVE6tqDdJoJ9Vn1dn+lW1TaOCrtKRSakPcFxgTXMv608Q==eTSQnxCMco7P/0vqpsQXNPo4Oi49f1WJrXvgG19gYNUl4x/hMRj80tbwPAgZ71wo7DImNgB+HYwROReYNJx8xcWlOe5O0EvJdCR9/KQvL/R0ESV83DSuKhtg3UU5uPicXz/FM/YZQbvEBRjCHAp+PdzNIqFuPQ09RweRQLhUVQjkVrQD87++xfK/z7lzGmubPZkyTQDdmLtpOJMBwGbFKfBxanbbC8r0pHYp05HI5dTbwuyNv+s/Kmu+EbVM4S5iBhqMGfbnoEk1sFnsU24ZY1NE/wbEsgkWBJZYdKxrp2S0DntD4fFD7CReZ7CXvAbfWoUYlTFnm9gV6oRZ/PaVPN/+/gKXF/wmOa0aYG8uLw1M63nRnfmfeEzOWuzxZk+VNQcXFLvITYLgLTLT63T4lCUmiJ7G/nuVKzhYfcI8D0wOc1/2fx5QFc4VCT0mELrLvyMnQMyd1mGjYVfIYFOA/ZPJwOgK94laxuNjhm6GeLIMsMEUQbnRcCY2537B2Q2+4Le0a1IMVy42uR2k4NE6"}',
            "attributes": {
                "ApproximateReceiveCount": "1",
                "SentTimestamp": "1696523461711",
                "SenderId": "",
                "ApproximateFirstReceiveTimestamp": "1696523461713",
            },
            "messageAttributes": {},
            "md5OfBody": "8834e454e4e0a22f7259a1cb0bcc66ce",
            "eventSource": "aws:sqs",
            "eventSourceARN": "arn:aws:sqs:us-east-1:111111111:asr-admin-stack1-SchedulingQueueB533E3CD-MGicwhGIVhFy",
            "awsRegion": "us-east-1",
        }
    ]
}

record = event["Records"][0]
body = json.loads(record["body"])  # type: ignore [arg-type]
remediation_details = body["RemediationDetails"]

get_item_parameters = {
    "TableName": "TestTable",
    "Key": {"AccountID-Region": {"S": f"{body['AccountId']}-{body['ResourceRegion']}"}},
}

table_key = f"{body['AccountId']}-{body['ResourceRegion']}"
table_name = os.environ.get("SchedulingTableName")


def create_table():
    boto3.client("dynamodb").create_table(
        AttributeDefinitions=[
            {"AttributeName": "AccountID-Region", "AttributeType": "S"}
        ],
        TableName=table_name,
        KeySchema=[{"AttributeName": "AccountID-Region", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )


@mock_aws
def test_new_account_remediation(mocker):
    dynamodb_client = boto3.client("dynamodb", config=BOTO_CONFIG)
    sfn_client = boto3.client("stepfunctions", config=BOTO_CONFIG)
    sfn_stub = Stubber(sfn_client)
    clients = {"dynamodb": dynamodb_client, "stepfunctions": sfn_client}
    create_table()

    current_timestamp = int(datetime.now(timezone.utc).timestamp())

    current_timestamp_string = datetime.fromtimestamp(
        current_timestamp, timezone.utc
    ).strftime(timestampFormat)

    output = {"PlannedTimestamp": current_timestamp_string}

    output.update(remediation_details)

    sfn_stub.add_response(
        "send_task_success",
        {},
        {"taskToken": body["TaskToken"], "output": json.dumps(output)},
    )

    sfn_stub.activate()
    with patch(client, side_effect=lambda service, **_: clients[service]):
        response = lambda_handler(event, {})
        final_item = dynamodb_client.get_item(
            TableName=table_name, Key={"AccountID-Region": {"S": table_key}}
        )
        assert final_item["Item"]["LastExecutedTimestamp"]["S"] == str(
            current_timestamp
        )
        assert (
            response
            == f"Remediation scheduled to execute at {current_timestamp_string}"
        )

    sfn_stub.deactivate()


@mock_aws
def test_no_recent_remediation(mocker):
    dynamodb_client = boto3.client("dynamodb", config=BOTO_CONFIG)
    sfn_client = boto3.client("stepfunctions", config=BOTO_CONFIG)
    sfn_stub = Stubber(sfn_client)
    clients = {"dynamodb": dynamodb_client, "stepfunctions": sfn_client}
    create_table()
    current_timestamp = int(datetime.now(timezone.utc).timestamp())

    found_timestamp = current_timestamp - 10

    dynamodb_client.put_item(
        TableName=table_name,
        Item={
            "AccountID-Region": {"S": table_key},
            "LastExecutedTimestamp": {"S": str(found_timestamp)},
        },
    )

    current_timestamp_string = datetime.fromtimestamp(
        current_timestamp, timezone.utc
    ).strftime(timestampFormat)

    output = {"PlannedTimestamp": current_timestamp_string}

    output.update(remediation_details)

    sfn_stub.add_response(
        "send_task_success",
        {},
        {"taskToken": body["TaskToken"], "output": json.dumps(output)},
    )

    sfn_stub.activate()

    with patch(client, side_effect=lambda service, **_: clients[service]):
        response = lambda_handler(event, {})
        final_item = dynamodb_client.get_item(
            TableName=table_name, Key={"AccountID-Region": {"S": table_key}}
        )
        assert final_item["Item"]["LastExecutedTimestamp"]["S"] == str(
            current_timestamp
        )
        assert (
            response
            == f"Remediation scheduled to execute at {current_timestamp_string}"
        )

    sfn_stub.deactivate()


@mock_aws
def test_recent_remediation(mocker):
    dynamodb_client = boto3.client("dynamodb", config=BOTO_CONFIG)
    sfn_client = boto3.client("stepfunctions", config=BOTO_CONFIG)
    sfn_stub = Stubber(sfn_client)
    clients = {"dynamodb": dynamodb_client, "stepfunctions": sfn_client}
    current_timestamp = int(datetime.now(timezone.utc).timestamp())
    found_timestamp = current_timestamp + 100

    create_table()
    dynamodb_client.put_item(
        TableName=table_name,
        Item={
            "AccountID-Region": {"S": table_key},
            "LastExecutedTimestamp": {"S": str(found_timestamp)},
        },
    )

    new_timestamp = found_timestamp + 3

    planned_timestamp = datetime.fromtimestamp(new_timestamp, timezone.utc).strftime(
        timestampFormat
    )

    output = {"PlannedTimestamp": planned_timestamp}

    output.update(remediation_details)

    sfn_stub.add_response(
        "send_task_success",
        {},
        {"taskToken": body["TaskToken"], "output": json.dumps(output)},
    )

    sfn_stub.activate()

    with patch(client, side_effect=lambda service, **_: clients[service]):
        response = lambda_handler(event, {})
        final_item = dynamodb_client.get_item(
            TableName=table_name, Key={"AccountID-Region": {"S": table_key}}
        )
        assert final_item["Item"]["LastExecutedTimestamp"]["S"] == str(new_timestamp)
        assert response == f"Remediation scheduled to execute at {planned_timestamp}"

    sfn_stub.deactivate()


@mock_aws
def test_account_missing_last_executed(mocker):
    dynamodb_client = boto3.client("dynamodb", config=BOTO_CONFIG)
    sfn_client = boto3.client("stepfunctions", config=BOTO_CONFIG)
    sfn_stub = Stubber(sfn_client)
    clients = {"dynamodb": dynamodb_client, "stepfunctions": sfn_client}
    create_table()

    dynamodb_client.put_item(
        TableName=table_name,
        Item={"AccountID-Region": {"S": table_key}},
    )

    current_timestamp = int(datetime.now(timezone.utc).timestamp())

    current_timestamp_string = datetime.fromtimestamp(
        current_timestamp, timezone.utc
    ).strftime(timestampFormat)

    output = {"PlannedTimestamp": current_timestamp_string}

    output.update(remediation_details)

    sfn_stub.add_response(
        "send_task_success",
        {},
        {"taskToken": body["TaskToken"], "output": json.dumps(output)},
    )

    sfn_stub.activate()
    with patch(client, side_effect=lambda service, **_: clients[service]):
        response = lambda_handler(event, {})
        final_item = dynamodb_client.get_item(
            TableName=table_name, Key={"AccountID-Region": {"S": table_key}}
        )
        assert final_item["Item"]["LastExecutedTimestamp"]["S"] == str(
            current_timestamp
        )
        assert (
            response
            == f"Remediation scheduled to execute at {current_timestamp_string}"
        )

    sfn_stub.deactivate()


def test_failure(mocker):
    sfn_client = boto3.client("stepfunctions", config=BOTO_CONFIG)
    sfn_stub = Stubber(sfn_client)
    clients = {"stepfunctions": sfn_client}
    os.environ["RemediationWaitTime"] = "NOT A NUMBER"

    sfn_stub.add_response(
        "send_task_failure",
        {},
        {
            "cause": "invalid literal for int() with base 10: 'NOT A NUMBER'",
            "error": "ValueError",
            "taskToken": body["TaskToken"],
        },
    )

    sfn_stub.activate()
    with patch(client, side_effect=lambda service, **_: clients[service]):
        lambda_handler(event, {})

    sfn_stub.deactivate()
