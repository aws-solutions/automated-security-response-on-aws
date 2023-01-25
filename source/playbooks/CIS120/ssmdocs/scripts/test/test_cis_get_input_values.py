# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import pytest

from cis_get_input_values import verify

def expected():
    return {
        "filter_name": "SHARR_Filter_CIS_1_2_Finding_3_13_RouteTableChanges",
        "filter_pattern": '{($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable)}',
        "metric_name": "SHARR_CIS_1_2_Finding_3_13_RouteTableChanges",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_CIS_1_2_Finding_3_13_RouteTableChanges",
        "alarm_desc": "Alarm for CIS finding 3.13 RouteTableChanges",
        "alarm_threshold": 1
    }

def test_verify():
    assert verify({'ControlId': '3.13'}, {}) == expected()
