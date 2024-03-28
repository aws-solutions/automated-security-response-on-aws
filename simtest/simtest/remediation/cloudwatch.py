# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.remediation_test import RemediationTest


def run_log_and_filter(remediation, account, region):
    print("This test creates a log metric filter and alarm")

    print("SETUP\n=====\n")
    print("None required.\n")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    # # Alter the test data
    # vpc_id = input('From the console, get the VPC ID of a VPC. This test will enable VPC Flow Logs: ')
    # test.test_json['detail']['findings'][0]['Resources'][0]['Id'] = "arn:aws:ec2:" + \
    #     region + ":111111111111:vpc/" + vpc_id

    test.run()

    print(
        "\nOpen the Log Group (from SSM Parameter Solutions/SO0111/Metrics_LogGroupName."
    )
    print('Click "Metric filters"')
    print("Verify that the metric for SHARR exists and has an alarm defined.")
