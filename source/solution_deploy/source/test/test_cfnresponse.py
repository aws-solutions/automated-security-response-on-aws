# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test cfnresponse"""

import json
import os
from unittest.mock import ANY

import cfnresponse
import pytest

os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_PARTITION"] = "aws"


@pytest.fixture()
def urllib_mock(mocker):
    yield mocker.patch("cfnresponse.http")


@pytest.fixture()
def event():
    yield {
        "ResponseURL": "response_url",
        "StackId": "stack_id",
        "RequestId": "request_id",
        "LogicalResourceId": "logical_resource_id",
    }


class Context:
    def __init__(self, log_stream_name):
        self.log_stream_name = log_stream_name


@pytest.fixture()
def context():
    yield Context("log_stream_name")


def body_correct(
    body,
    event,
    context,
    status,
    response_data,
    physical_resource_id=None,
    no_echo=False,
    reason=None,
):
    assert body["Status"] == status
    assert body["StackId"] == event["StackId"]
    assert body["RequestId"] == event["RequestId"]
    assert body["LogicalResourceId"] == event["LogicalResourceId"]
    if physical_resource_id is not None:
        assert body["PhysicalResourceId"] == physical_resource_id
    else:
        assert body["PhysicalResourceId"] == context.log_stream_name
    assert body["NoEcho"] == no_echo
    if reason is not None:
        assert body["Reason"] == reason
    else:
        assert context.log_stream_name in body["Reason"]
    assert body["Data"] == response_data
    return True


def test_send(urllib_mock, event, context):
    status = cfnresponse.SUCCESS
    response_data: dict[str, str] = {}
    cfnresponse.send(event, context, status, response_data)
    urllib_mock.request.assert_called_once_with(
        "PUT", event["ResponseURL"], body=ANY, headers=ANY
    )
    _, _, call_kwargs = urllib_mock.request.mock_calls[0]
    assert body_correct(
        json.loads(call_kwargs["body"]), event, context, status, response_data
    )
    assert call_kwargs["headers"]["content-length"] == str(len(call_kwargs["body"]))


def test_send_with_reason(urllib_mock, event, context):
    status = cfnresponse.FAILED
    response_data = {"some": "data", "key": "value"}
    physical_resource_id = "some_id"
    no_echo = True
    reason = "some_reason"
    cfnresponse.send(
        event, context, status, response_data, physical_resource_id, no_echo, reason
    )
    urllib_mock.request.assert_called_once_with(
        "PUT", event["ResponseURL"], body=ANY, headers=ANY
    )
    _, _, call_kwargs = urllib_mock.request.mock_calls[0]
    assert body_correct(
        json.loads(call_kwargs["body"]),
        event,
        context,
        status,
        response_data,
        physical_resource_id,
        no_echo,
        reason,
    )
    assert call_kwargs["headers"]["content-length"] == str(len(call_kwargs["body"]))


def test_send_exception(urllib_mock, event, context):
    urllib_mock.request.side_effect = Exception()
    cfnresponse.send(event, context, cfnresponse.FAILED, {})
