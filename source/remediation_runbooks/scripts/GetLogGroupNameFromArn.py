# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict


class GetLogGroupNameFromArnEvent(TypedDict):
    Arn: str


def get_log_group_name_from_arn(event: GetLogGroupNameFromArnEvent, _) -> str:
    return event["Arn"].split(":")[6]
