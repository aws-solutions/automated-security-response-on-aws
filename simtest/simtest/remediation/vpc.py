# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.remediation_test import RemediationTest


def run_enable_vpc_flow_logs(remediation, account, region):
    print("This test enables VPC Flow Logging for a VPC.\n")

    print("SETUP\n=====\n")
    print("1) Use the default VPC (or create a new VPC)\n")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    # Alter the test data
    vpc_id = input(
        "From the console, get the VPC ID of a VPC. This test will enable VPC Flow Logs: "
    )
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "arn:aws:ec2:" + region + ":" + account + ":vpc/" + vpc_id
    )

    test.run()

    print(
        "\nVerify that flow logs are enabled for the VPC. If it was already enabled, check the lambda logs for errors. Optionally, disable flow logs and rerun this test."
    )
