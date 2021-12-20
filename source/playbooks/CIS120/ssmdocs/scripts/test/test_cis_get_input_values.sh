#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################
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
