# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json


def runbook_handler(event: dict[str, object], _: object) -> str:
    # Rollback removes the ASR statement by Sid from the snapshot, so no denylist is needed — and none is
    # resolvable, since the finding reconstructed for a rollback carries no ProductFields.
    if event.get("Rollback") == "ROLLBACK":
        return ""
    serialized = event.get("SerializedList")
    if not isinstance(serialized, str) or not serialized:
        raise ValueError(
            "Missing or invalid required parameter: SerializedList (expected the AWS Config rule InputParameters JSON)"
        )
    try:
        deserialized = json.loads(serialized)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"SerializedList is not valid JSON (expected the AWS Config rule InputParameters): {error}"
        ) from error
    pattern = (
        deserialized.get("blacklistedActionPattern")
        if isinstance(deserialized, dict)
        else None
    )
    if not isinstance(pattern, str):
        raise ValueError("Missing blacklistedActionPattern in AWS Config data")
    return pattern  # Comma-delimited list in a string
