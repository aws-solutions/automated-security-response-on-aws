# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.remediation_test import RemediationTest


def run_s3_block_public_access(remediation, account, region):
    print("Test setting S3 public access block at the account level.\n")

    print("Manual Setup")
    print("============\n")
    print("1) Go to S3 in the console")
    print("2) Go to Block Public Access settings for this account")
    print("3) Edit settings and uncheck all boxes")
    print("4) Save settings")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "AWS::::Account:" + account
    )

    test.run()

    print("\nVERIFICATION\n============\n")
    print("1) In S3, verify account-level public access blocks are enabled.")


def run_s3_block_public_bucket_access(remediation, account, region):
    print("Test setting S3 public access block at the account level.\n")

    print("Manual Setup")
    print("============\n")
    print("1) Go to S3 in the console")
    print(
        '2) Choose a bucket to test with and open "Block public access" settings in "Permissions"'
    )
    print("3) Edit settings and uncheck all boxes")
    print("4) Save settings")

    test_bucket = input("\nBucket name?: ")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)
    test.test_json["detail"]["findings"][0]["Resources"][0][
        "Id"
    ] = f"arn:aws:s3:::{test_bucket}"

    test.run()

    print("\nVERIFICATION\n============\n")
    print(f"1) In S3, verify bucket {test_bucket} public access blocks are enabled.")
