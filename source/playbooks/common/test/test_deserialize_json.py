# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

from deserialize_json import event_handler


def event(object):
    return {"SerializedJson": json.dumps(object)}


def test_deserialize():
    object = {"MinRetentionPeriod": "7"}
    assert event_handler(event(object), {}) == object
