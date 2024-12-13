# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict


class AppendSuffixEvent(TypedDict):
    OriginalString: str
    MaxLen: int
    Suffix: str


def append_suffix(event: AppendSuffixEvent, _) -> str:
    prefix_len = event["MaxLen"] - len(event["Suffix"])
    new_name = event["OriginalString"][:prefix_len] + event["Suffix"]
    return new_name
