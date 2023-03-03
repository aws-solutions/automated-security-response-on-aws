# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import pytest

from cis_get_input_values import verify

def expected():
    return {
        "filter_name": "RouteTableChanges",
        "filter_pattern": '{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}',
        "metric_name": "RouteTableChanges",
        "metric_value": 1,
        "alarm_name": "RouteTableChanges",
        "alarm_desc": "Alarm for RouteTableChanges > 0",
        "alarm_threshold": 1
    }

def test_verify():
    assert verify({'ControlId': 'Cloudwatch.13'}, {}) == expected()
