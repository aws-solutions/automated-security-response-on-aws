# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re


def parse_non_string_types(param):
    if re.match("^\d+$", str(param)):
        param = int(param)
        return param
    if param == "true" or param == "True":
        return True
    if param == "false" or param == "False":
        return False
    if isinstance(param, list):
        return param
    if len(param.split(",")) > 1:
        return param.split(",")
    return param


def get_input_params(event, _):
    security_hub_input_params = event["SecHubInputParams"]

    default_params = event["DefaultParams"]

    input_params = {}

    for param in default_params:
        if param in security_hub_input_params:
            converted_param = parse_non_string_types(security_hub_input_params[param])
            input_params[param] = converted_param
        else:
            converted_param = parse_non_string_types(default_params[param])
            input_params[param] = converted_param

    return input_params
