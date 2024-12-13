# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from get_input_params import get_input_params


def test_get_input_params_int():
    event = {"SecHubInputParams": {}, "DefaultParams": {"myParam": 2}}

    result = get_input_params(event, None)
    assert result["myParam"] == 2


def test_get_input_params_string():
    event = {
        "SecHubInputParams": {"myParam": "myValue2"},
        "DefaultParams": {"myParam": "myValue1"},
    }

    result = get_input_params(event, None)
    assert result["myParam"] == "myValue2"


def test_get_input_params_string_bool():
    event = {
        "SecHubInputParams": {"myParam": "FaLsE"},
        "DefaultParams": {"myParam": "TrUE"},
    }

    result = get_input_params(event, None)
    assert result["myParam"] is False


def test_get_input_params_bool():
    event = {
        "SecHubInputParams": {"myParam": True},
        "DefaultParams": {"myParam": False},
    }

    result = get_input_params(event, None)
    assert result["myParam"] is True


def test_get_input_params_list():
    event = {
        "SecHubInputParams": {"myParam": ["val1", "val2"]},
        "DefaultParams": {"myParam": ["someVal"]},
    }

    result = get_input_params(event, None)
    assert result["myParam"] == ["val1", "val2"]


def test_get_input_params_comma_delim():
    event = {
        "SecHubInputParams": {"myParam": "val1,val2"},
        "DefaultParams": {"myParam": "someVal"},
    }

    result = get_input_params(event, None)
    assert result["myParam"] == ["val1", "val2"]
