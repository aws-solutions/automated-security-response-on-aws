# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json


def event_handler(event, _):
    try:
        return json.loads(event["SerializedJson"])
    except Exception as e:
        print(e)
        exit("Failed to deserialize data")
