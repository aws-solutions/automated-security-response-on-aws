# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.remediation_test import RemediationTest


def run_autoscaling_1(remediation, account, region):
    print("This test enables ELB health checks on an autoscaling group.\n")

    print("Manual Setup")
    print("============\n")
    print("1) Select an Autoscaling group attached to an ELB to test with.")
    print("2) Disable ELB health checks")
    asg_name = input("\nAutoscaling group name? ")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0][
        "Id"
    ] = f"arn:aws:autoscaling:{region}:{account}:autoScalingGroup:785df3481e1-cd66-435d-96de-d6ed5416defd:autoScalingGroupName/{asg_name}"

    test.run()

    print("\nVERIFICATION\n============\n")
    print("1) Verify that ELB health check is enabled on the autoscaling group.")
