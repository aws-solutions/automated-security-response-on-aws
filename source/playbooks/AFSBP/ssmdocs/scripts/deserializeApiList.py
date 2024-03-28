# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json


def runbook_handler(event, _):
    try:
        deserialized = json.loads(event["SerializedList"])
        if "blacklistedActionPattern" in deserialized:
            return deserialized[
                "blacklistedActionPattern"
            ]  # Returns comma-delimited list in a string
        else:
            exit("Missing blacklistedActionPattern in AWS Config data")
    except Exception as e:
        print(e)
        exit(
            "Failed getting comma-delimited string list of sensitive API calls input data"
        )
