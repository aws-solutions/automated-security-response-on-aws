# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
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
