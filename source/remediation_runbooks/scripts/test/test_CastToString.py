# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import pytest
from CastToString import cast_to_string


def test_cast_to_string():
    event = {"DesiredParameter": "StringValue", "StringValue": "hello"}
    response = cast_to_string(event, None)
    assert response == "hello"

    event = {"DesiredParameter": "IntValue", "IntValue": 42}
    response = cast_to_string(event, None)
    assert response == "42"

    event = {"DesiredParameter": "FloatValue", "FloatValue": 3.14}
    response = cast_to_string(event, None)
    assert response == "3.14"

    with pytest.raises(KeyError):
        cast_to_string({"DesiredParameter": "MissingValue"}, None)
