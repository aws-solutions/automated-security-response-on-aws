# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import Mock

MOTO_ACCOUNT_ID = "123456789012"


def create_lambda_context():
    context = Mock()
    context.function_name = "test-function"
    context.function_version = "$LATEST"
    context.invoked_function_arn = (
        "arn:aws:lambda:us-east-1:123456789012:function:test-function"
    )
    context.memory_limit_in_mb = 128
    context.remaining_time_in_millis = lambda: 30000
    context.aws_request_id = "test-request-id-123"
    context.log_group_name = "/aws/lambda/test-function"
    context.log_stream_name = "2021/01/01/[$LATEST]test-stream"
    context.identity = Mock()
    context.client_context = Mock()
    return context
