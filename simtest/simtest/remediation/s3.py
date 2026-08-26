# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.remediation_test import RemediationTest

_MANUAL_SETUP_HEADER = "Manual Setup"
_SECTION_DIVIDER = "============\n"
_VERIFICATION_HEADER = "\nVERIFICATION\n============\n"


def run_s3_block_public_access(remediation, account):
    print("Test setting S3 public access block at the account level.\n")

    print(_MANUAL_SETUP_HEADER)
    print(_SECTION_DIVIDER)
    print("1) Go to S3 in the console")
    print("2) Go to Block Public Access settings for this account")
    print("3) Edit settings and uncheck all boxes")
    print("4) Save settings")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "AWS::::Account:" + account
    )

    test.run()

    print(_VERIFICATION_HEADER)
    print("1) In S3, verify account-level public access blocks are enabled.")


def run_s3_block_public_bucket_access(remediation, account):
    print("Test setting S3 public access block at the account level.\n")

    print(_MANUAL_SETUP_HEADER)
    print(_SECTION_DIVIDER)
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

    print(_VERIFICATION_HEADER)
    print(f"1) In S3, verify bucket {test_bucket} public access blocks are enabled.")


def run_s3_enable_versioning(remediation: str, account: str) -> None:
    print("Test enabling S3 bucket versioning.\n")

    print(_MANUAL_SETUP_HEADER)
    print(_SECTION_DIVIDER)
    print("1) Create an S3 bucket (or use an existing one) without versioning enabled")
    print("2) Verify versioning is Suspended or not set")

    test_bucket = input("\nBucket name?: ")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)
    finding = test.test_json["detail"]["findings"][0]
    finding["Resources"][0]["Id"] = f"arn:aws:s3:::{test_bucket}"
    finding["Resources"][0]["Region"] = test.orchestrator.get_region()
    # Fix finding Id to use the actual account (parse_input validates it)
    region = test.orchestrator.get_region()
    finding["Id"] = (
        f"arn:aws:securityhub:{region}:{account}:"
        "security-control/S3.14/finding/e8e66086-096c-4faf-8a05-52f138b4b748"
    )
    finding["ProductFields"][
        "aws/securityhub/FindingId"
    ] = f"arn:aws:securityhub:{region}::product/aws/securityhub/{finding['Id']}"

    test.run()

    print(_VERIFICATION_HEADER)
    print(f"1) In S3, verify bucket {test_bucket} has versioning Enabled.")
