# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.remediation_test import RemediationTest


def run_setup_key_rotation(remediation, account, region):
    print("This test enables rotation on a KMS key.\n")

    print("SETUP\n=====\n")
    print(
        "1) Create a symmetric KMS Customer-Managed Key, leaving CMK rotation disabled.\n"
    )

    test = RemediationTest(remediation, account)

    # Alter the test data
    key_id = input("CMK Id: ")
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "AWS::KMS::Key:" + key_id
    )

    test.run()

    print(
        "\nVerify that Key rotation is enabled for the key. If it was already enabled, check the lambda logs for errors. Optionally, disable key rotation and rerun this test."
    )
