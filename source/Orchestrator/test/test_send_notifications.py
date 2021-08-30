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

"""
Unit Test: exec_ssm_doc.py
Run from /deployment/temp/source/Orchestrator after running build-s3-dist.sh
"""

import os
from send_notifications import lambda_handler
from pytest_mock import mocker

event = {
    'Notification': {
        'State': 'SUCCESS',
        'Message': 'A Door is Ajar'
    },
    'SecurityStandard': 'AFSBP',
    'ControlId': 'foobar.1'
}
def test_resolved(mocker):
    event = {
        'Notification': {
            'State': 'SUCCESS',
            'Message': 'A Door is Ajar'
        },
        'SecurityStandard': 'AFSBP',
        'ControlId': 'foobar.1'
    }
    mocker.patch('send_notifications.sechub_findings.SHARRNotification.notify', return_value=None)
    assert lambda_handler(event, {}) == None

def test_wrong_standard(mocker):
    event = {
        'Notification': {
            'State': 'WRONGSTANDARD',
            'Message': 'A Door is Ajar'
        },
        'SecurityStandard': 'AFSBP',
        'ControlId': 'foobar.1'
    }
    mocker.patch('send_notifications.sechub_findings.SHARRNotification.notify', return_value=None)
    assert lambda_handler(event, {}) == None

