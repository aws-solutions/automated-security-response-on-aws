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

from pci_get_input_values import verify

def expected(): 
    return {
        "filter_name": "SHARR_Filter_PCI_321_Finding_CW1_RootAccountUsage",
        "filter_pattern": '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}',
        "metric_name": "SHARR_PCI_321_Finding_CW1_RootAccountUsage",
        "metric_value": 1,
        "alarm_name": "SHARR_Alarm_PCI_321_Finding_CW1_RootAccountUsage",
        "alarm_desc": "Alarm for PCI finding CW.1 RootAccountUsage",
        "alarm_threshold": 1
    }

def test_verify():
    assert verify({'ControlId': 'PCI.CW.1'}, {}) == expected()
