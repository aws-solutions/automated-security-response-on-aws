# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import time
from datetime import date
from typing import List, Optional, Tuple

from botocore.exceptions import ClientError
from layer import awsapi_cached_client

# Constants
LOG_MAX_BATCH_SIZE = 1048576
LOG_ENTRY_ADDITIONAL = 26
DEFAULT_REGION = "us-east-1"
DEFAULT_LOG_GROUP = "SO0111-ASR"
MAX_CREATE_STREAM_RETRIES = 3  # Maximum number of recursive attempts


def get_logs_connection(apiclient):
    return apiclient.get_connection("logs")


class FailedToCreateLogGroup(Exception):
    pass


class LogHandler:
    def __init__(self, stream_name: str):
        self.apiclient = awsapi_cached_client.AWSCachedClient(
            os.getenv("AWS_DEFAULT_REGION", DEFAULT_REGION)
        )
        self.stream_name = stream_name.upper()
        self.log_group = os.getenv("SOLUTION_LOGGROUP", DEFAULT_LOG_GROUP)
        self._buffer: List[Tuple[int, str]] = []
        self._buffer_size: int = 0
        self._current_stream: Optional[str] = None
        self.logs_client = get_logs_connection(self.apiclient)

    def _create_log_group(self) -> bool:
        try:
            self.logs_client.create_log_group(logGroupName=self.log_group)
            return True
        except ClientError as e:
            # If the log group already exists, consider it a success
            if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
                return True
            # For any other error, consider it a failure
            return False

    def _create_log_stream(self, log_stream: str, retry_count: int = 0) -> str:
        dated_stream = f"{log_stream}-{date.today()}"

        if self._current_stream == dated_stream:
            return dated_stream

        self._current_stream = dated_stream

        while retry_count <= MAX_CREATE_STREAM_RETRIES:
            try:
                self.logs_client.create_log_stream(
                    logGroupName=self.log_group, logStreamName=dated_stream
                )
                return dated_stream

            except ClientError as e:
                error_code = e.response["Error"]["Code"]

                if error_code == "ResourceAlreadyExistsException":
                    return dated_stream

                if error_code == "ResourceNotFoundException":
                    if not self._create_log_group():
                        raise FailedToCreateLogGroup(
                            f"Failed to create log group {self.log_group}"
                        )

                    retry_count += 1
                    continue

                raise

        raise FailedToCreateLogGroup(
            f"Failed to create log stream after {MAX_CREATE_STREAM_RETRIES} attempts"
        )

    def add_message(self, message: str) -> None:
        message = message or "   "  # Handle empty messages
        timestamp = int(time.time() * 1000)
        message_size = len(message) + LOG_ENTRY_ADDITIONAL

        if self._buffer_size + message_size > LOG_MAX_BATCH_SIZE:
            self.flush()

        self._buffer.append((timestamp, message))
        self._buffer_size += message_size

    def flush(self) -> None:
        if not self._buffer:
            return

        log_stream = self._create_log_stream(self.stream_name)

        try:
            self.logs_client.put_log_events(
                logGroupName=self.log_group,
                logStreamName=log_stream,
                logEvents=[
                    {"timestamp": ts, "message": msg}
                    for ts, msg in sorted(self._buffer)
                ],
            )
        except ClientError as e:
            print(f"Error writing to log stream {self.stream_name}: {str(e)}")
        finally:
            self.clear()

    def clear(self) -> None:
        self._buffer = []
        self._buffer_size = 0
