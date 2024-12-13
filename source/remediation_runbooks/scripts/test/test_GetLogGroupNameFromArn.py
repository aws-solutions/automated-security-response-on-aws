# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from GetLogGroupNameFromArn import get_log_group_name_from_arn


def test_get_log_group_name_from_arn():
    arn = "arn:aws:logs:us-east-1:111111111111:log-group:/aws/apigateway/welcome"
    result = get_log_group_name_from_arn({"Arn": arn}, None)
    assert result == "/aws/apigateway/welcome"
