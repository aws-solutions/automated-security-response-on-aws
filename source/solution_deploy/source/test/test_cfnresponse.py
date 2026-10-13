# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test cfnresponse"""

import json
import os
import time
from unittest.mock import ANY

import cfnresponse
import pytest
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import MaxRetryError

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


def test_redact_presigned_url_strips_query_string():
    presigned = (
        "https://bucket.s3.amazonaws.com/key?"
        "X-Amz-Credential=AKIAEXAMPLE/20260101/us-east-1/s3/aws4_request&"
        "X-Amz-Signature=abcdef0123456789&"
        "X-Amz-Security-Token=FwoGZXIvSESSIONTOKEN&X-Amz-Expires=3600"
    )
    redacted = cfnresponse.redact_presigned_url(presigned)
    # Every sensitive query parameter is gone, including the session token.
    assert "AKIAEXAMPLE" not in redacted
    assert "abcdef0123456789" not in redacted
    assert "FwoGZXIvSESSIONTOKEN" not in redacted
    # The base URL (no secrets) is preserved for diagnostics.
    assert "https://bucket.s3.amazonaws.com/key?*****" in redacted


def test_send_exception_redacts_presigned_url(urllib_mock, event, context, capsys):
    signed_url = (
        "https://bucket.s3.amazonaws.com/key?"
        "X-Amz-Credential=AKIALEAK/20260101/us-east-1/s3/aws4_request&"
        "X-Amz-Signature=deadbeefsignature&X-Amz-Security-Token=SESSIONLEAK"
    )
    event["ResponseURL"] = signed_url
    urllib_mock.request.side_effect = Exception(f"failed PUT to {signed_url}")
    cfnresponse.send(event, context, cfnresponse.FAILED, {})
    printed = capsys.readouterr().out
    # The bare ResponseURL is never printed, and no signing parameter that rides
    # in on the exception message leaks (credential, signature, or session token).
    assert "AKIALEAK" not in printed
    assert "deadbeefsignature" not in printed
    assert "SESSIONLEAK" not in printed


def test_redact_presigned_url_strips_bare_path_query_string():
    # A urllib3 MaxRetryError renders the URL as a bare path with no scheme.
    message = (
        "HTTPSConnectionPool(host='bucket.s3.amazonaws.com', port=None): "
        "Max retries exceeded with url: "
        "/key?X-Amz-Signature=deadbeef&X-Amz-Security-Token=SESSIONLEAK "
        "(Caused by NewConnectionError('boom'))"
    )
    redacted = cfnresponse.redact_presigned_url(message)
    assert "deadbeef" not in redacted
    assert "SESSIONLEAK" not in redacted
    # The query is redacted in place and the trailing context is preserved.
    assert "url: /key?*****" in redacted
    assert "(Caused by NewConnectionError('boom'))" in redacted


def test_redact_presigned_url_leaves_text_without_query_unchanged():
    message = "HTTPSConnectionPool(host='bucket.s3.amazonaws.com'): timed out"
    assert cfnresponse.redact_presigned_url(message) == message


def test_redact_presigned_url_runs_in_linear_time_on_long_input():
    # A long run with no "?" made the earlier pattern backtrack quadratically
    # (about 7 seconds at 40k characters). The linear pattern handles it at once.
    message = "a" * 100_000
    start = time.monotonic()
    assert cfnresponse.redact_presigned_url(message) == message
    assert time.monotonic() - start < 1


def test_send_redacts_presigned_url_from_max_retry_error(
    urllib_mock, event, context, capsys
):
    # Reproduce the real failure: retries exhausted, so urllib3 raises a
    # MaxRetryError whose message carries the bare-path presigned URL.
    signed_path = (
        "/key?X-Amz-Signature=deadbeefsignature&X-Amz-Security-Token=SESSIONLEAK"
    )
    pool = HTTPSConnectionPool("bucket.s3.amazonaws.com")
    urllib_mock.request.side_effect = MaxRetryError(
        pool, signed_path, reason=Exception("boom")
    )
    cfnresponse.send(event, context, cfnresponse.FAILED, {})
    printed = capsys.readouterr().out
    assert "deadbeefsignature" not in printed
    assert "SESSIONLEAK" not in printed
