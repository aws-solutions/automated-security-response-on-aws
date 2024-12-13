# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
def cast_to_string(event, _) -> str:
    parameter_to_cast = event["DesiredParameter"]
    return str(event[parameter_to_cast])
