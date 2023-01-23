# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.remediation_test import RemediationTest
from simtest.boto_session import get_session

def run_guardduty_1(remediation, account, region):
    print('Simulate AFSBP GuardDuty.1 Findings\n')

    print('This test enables GuardDuty in the finding region.\n')

    print('Automatic Setup')
    print('============\n')
    print('1) Delete all GuardDuty detectors.\n')
    input('HIT ENTER TO START')

    delete_all_guardduty_detectors()

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json['detail']['findings'][0]['Resources'][0]['Id'] = 'AWS::::Account:' + account

    test.run()

    print('\nVERIFICATION\n============\n')
    print(f'1) In GuardDuty Settings, verify that a Detector is active on a 6 hour interval.')

def delete_all_guardduty_detectors():
    """
    Run this only in a test account
    """
    aws = get_session()
    gd = aws.client('guardduty')
    try:
        detectors = gd.list_detectors().get('DetectorIds')
        for detector in detectors:
            gd.delete_detector(
                DetectorId=detector
                )
    except Exception as e:
        print(e)
        print('Something went wrong')
        raise
