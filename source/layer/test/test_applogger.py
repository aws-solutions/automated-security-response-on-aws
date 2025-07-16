# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import date

import boto3
import pytest
from botocore.stub import ANY, Stubber
from layer.applogger import (
    DEFAULT_LOG_GROUP,
    DEFAULT_REGION,
    LOG_ENTRY_ADDITIONAL,
    LOG_MAX_BATCH_SIZE,
    MAX_CREATE_STREAM_RETRIES,
    FailedToCreateLogGroup,
    LogHandler,
)


class MockAWSCachedClient:
    def __init__(self, region):
        self.region = region
        self.logs_client = boto3.client("logs", region_name=region)

    def get_connection(self, service):
        if service == "logs":
            return self.logs_client
        raise ValueError(f"Unexpected service: {service}")


class TestLogHandler:
    @pytest.fixture(autouse=True)
    def setup_environment(self, monkeypatch):

        monkeypatch.setenv("AWS_DEFAULT_REGION", DEFAULT_REGION)
        monkeypatch.setenv("SOLUTION_LOGGROUP", DEFAULT_LOG_GROUP)

    @pytest.fixture(scope="function")
    def mock_aws_client(self, mocker):
        mock_client = MockAWSCachedClient(DEFAULT_REGION)
        mocker.patch(
            "layer.applogger.awsapi_cached_client.AWSCachedClient",
            return_value=mock_client,
        )
        return mock_client

    def test_init_default(self):
        applogger = LogHandler("mystream")
        assert applogger.log_group == DEFAULT_LOG_GROUP
        assert applogger.stream_name == "MYSTREAM"

    def test_create_logstream(self, mock_aws_client):
        applogger = LogHandler("mystream")
        stream = f"MYSTREAM-{date.today()}"

        stubber = Stubber(mock_aws_client.logs_client)
        stubber.add_response(
            "create_log_stream",
            {},
            {"logGroupName": DEFAULT_LOG_GROUP, "logStreamName": stream},
        )
        stubber.add_response(
            "put_log_events",
            {},
            {
                "logGroupName": DEFAULT_LOG_GROUP,
                "logStreamName": stream,
                "logEvents": ANY,
            },
        )

        with stubber:
            applogger.add_message("test message")
            applogger.flush()

        stubber.assert_no_pending_responses()

    def test_empty_message(self):
        applogger = LogHandler("mystream")
        applogger.add_message("")
        assert applogger._buffer[0][1] == "   "

    def test_buffer_size_limit(self, mocker):
        applogger = LogHandler("mystream")
        mock_flush = mocker.patch.object(applogger, "flush")
        message_size = LOG_MAX_BATCH_SIZE - LOG_ENTRY_ADDITIONAL
        large_msg = "x" * message_size
        applogger.add_message(large_msg)
        applogger.add_message("extra")
        assert mock_flush.called

    def test_create_log_group_failure(self, mock_aws_client):
        applogger = LogHandler("mystream")
        stream = f"MYSTREAM-{date.today()}"

        stubber = Stubber(mock_aws_client.logs_client)
        stubber.add_client_error(
            "create_log_stream",
            "ResourceNotFoundException",
            "Log group does not exist",
            expected_params={
                "logGroupName": DEFAULT_LOG_GROUP,
                "logStreamName": stream,
            },
        )
        stubber.add_client_error(
            "create_log_group",
            "OperationAbortedException",
            "Operation aborted",
            expected_params={"logGroupName": DEFAULT_LOG_GROUP},
        )

        with stubber:
            with pytest.raises(FailedToCreateLogGroup) as excinfo:
                applogger._create_log_stream("MYSTREAM")

        assert "Failed to create log group" in str(excinfo.value)
        stubber.assert_no_pending_responses()

    def test_create_log_stream_max_retries(self, mock_aws_client):
        applogger = LogHandler("test-stream")
        stream = f"TEST-STREAM-{date.today()}"

        stubber = Stubber(mock_aws_client.logs_client)

        for i in range(MAX_CREATE_STREAM_RETRIES + 1):
            stubber.add_client_error(
                "create_log_stream",
                "ResourceNotFoundException",
                f"Log group not found (attempt {i+1})",
                expected_params={
                    "logGroupName": DEFAULT_LOG_GROUP,
                    "logStreamName": stream,
                },
            )
            stubber.add_response(
                "create_log_group", {}, {"logGroupName": DEFAULT_LOG_GROUP}
            )

        with stubber:
            with pytest.raises(FailedToCreateLogGroup) as excinfo:
                applogger._create_log_stream("TEST-STREAM")

        assert (
            f"Failed to create log stream after {MAX_CREATE_STREAM_RETRIES} attempts"
            in str(excinfo.value)
        )
        stubber.assert_no_pending_responses()

    def test_create_log_stream_race_condition(self, mock_aws_client):
        applogger = LogHandler("test-stream")
        stream = f"TEST-STREAM-{date.today()}"

        stubber = Stubber(mock_aws_client.logs_client)

        # First attempt - log group doesn't exist
        stubber.add_client_error(
            "create_log_stream",
            "ResourceNotFoundException",
            "Log group does not exist",
            expected_params={
                "logGroupName": DEFAULT_LOG_GROUP,
                "logStreamName": stream,
            },
        )

        # Create log group succeeds
        stubber.add_response(
            "create_log_group", {}, {"logGroupName": DEFAULT_LOG_GROUP}
        )

        # Second attempt - stream exists
        stubber.add_client_error(
            "create_log_stream",
            "ResourceAlreadyExistsException",
            "Log stream already exists",
            expected_params={
                "logGroupName": DEFAULT_LOG_GROUP,
                "logStreamName": stream,
            },
        )

        with stubber:
            result = applogger._create_log_stream("TEST-STREAM")
            assert result == stream

        stubber.assert_no_pending_responses()

    def test_clear_buffer(self):
        applogger = LogHandler("mystream")
        applogger.add_message("test")
        applogger.clear()
        assert len(applogger._buffer) == 0
        assert applogger._buffer_size == 0
