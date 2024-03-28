# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json


def load_test_data(file, region):
    testdata = open(file)
    rawdata = testdata.read()
    rawdata = rawdata.replace("us-east-1", region)
    # Replace all occurences of us-east-1 with <region>
    event = json.loads(rawdata)
    testdata.close
    return event
