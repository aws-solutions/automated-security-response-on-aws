# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `enable_delivery_status_logging` remediation script"""

from unittest.mock import patch

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from enable_delivery_status_logging import lambda_handler


def test_enables_delivery_status_logging(mocker):
    endpointTypes = ["HTTP", "Firehose", "Lambda", "Application", "SQS"]

    my_session = boto3.session.Session()
    my_region = my_session.region_name

    BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
    sns = boto3.client("sns", config=BOTO_CONFIG)
    stub_sns = Stubber(sns)
    clients = {"sns": sns}

    logging_arn = "logging_arn"
    topic_arn = f"arn:aws:sns:{my_region}:111111111111:sharr-test"

    stub_response = {
        "Attributes": {
            "LambdaFailureFeedbackRoleArn": logging_arn,
            "LambdaSuccessFeedbackRoleArn": logging_arn,
            "LambdaSuccessFeedbackSampleRate": "0",
            "HTTPFailureFeedbackRoleArn": logging_arn,
            "HTTPSuccessFeedbackRoleArn": logging_arn,
            "HTTPSuccessFeedbackSampleRate": "0",
            "FirehoseFailureFeedbackRoleArn": logging_arn,
            "FirehoseSuccessFeedbackRoleArn": logging_arn,
            "FirehoseSuccessFeedbackSampleRate": "0",
            "ApplicationFailureFeedbackRoleArn": logging_arn,
            "ApplicationSuccessFeedbackRoleArn": logging_arn,
            "ApplicationSuccessFeedbackSampleRate": "0",
            "SQSFailureFeedbackRoleArn": logging_arn,
            "SQSSuccessFeedbackRoleArn": logging_arn,
            "SQSSuccessFeedbackSampleRate": "0",
        }
    }
    for endpoint in endpointTypes:
        stub_sns.add_response(
            "set_topic_attributes",
            {},
            {
                "TopicArn": topic_arn,
                "AttributeName": f"{endpoint}SuccessFeedbackRoleArn",
                "AttributeValue": logging_arn,
            },
        )

        stub_sns.add_response(
            "set_topic_attributes",
            {},
            {
                "TopicArn": topic_arn,
                "AttributeName": f"{endpoint}FailureFeedbackRoleArn",
                "AttributeValue": logging_arn,
            },
        )

    for endpoint in endpointTypes:
        stub_sns.add_response(
            "set_topic_attributes",
            {},
            {
                "TopicArn": topic_arn,
                "AttributeName": f"{endpoint}SuccessFeedbackSampleRate",
                "AttributeValue": "0",
            },
        )

    stub_sns.add_response(
        "get_topic_attributes", stub_response, {"TopicArn": topic_arn}
    )

    stub_sns.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {
            "topic_arn": topic_arn,
            "logging_role": logging_arn,
            "sample_rate": "0",
        }
        response = lambda_handler(event, {})
        assert response == {
            "LambdaFailureFeedbackRoleArn": logging_arn,
            "LambdaSuccessFeedbackRoleArn": logging_arn,
            "LambdaSuccessFeedbackSampleRate": "0",
            "HTTPFailureFeedbackRoleArn": logging_arn,
            "HTTPSuccessFeedbackRoleArn": logging_arn,
            "HTTPSuccessFeedbackSampleRate": "0",
            "FirehoseFailureFeedbackRoleArn": logging_arn,
            "FirehoseSuccessFeedbackRoleArn": logging_arn,
            "FirehoseSuccessFeedbackSampleRate": "0",
            "ApplicationFailureFeedbackRoleArn": logging_arn,
            "ApplicationSuccessFeedbackRoleArn": logging_arn,
            "ApplicationSuccessFeedbackSampleRate": "0",
            "SQSFailureFeedbackRoleArn": logging_arn,
            "SQSSuccessFeedbackRoleArn": logging_arn,
            "SQSSuccessFeedbackSampleRate": "0",
        }
