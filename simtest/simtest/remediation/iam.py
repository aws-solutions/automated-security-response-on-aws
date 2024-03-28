# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.boto_session import get_session
from simtest.remediation_test import RemediationTest


def run_remove_old_credentials(remediation, account, region):
    print(
        "A full test requires an IAM user ID with keys/credentials older than 90 days. Unless you have a time machine, you may wish to simply test that the permissions allow the API calls without remediating any actual keys.\n"
    )
    print("SETUP\n=====\n")
    print("1) create an IAM user in the target account")
    print("2) Create an access key\n")
    print("Note: the test will fail if the IAM user has no active credentials.\n")

    test = RemediationTest(remediation, account, True)

    # key user
    key_user = input("Name of an IAM user: ")
    key_user_id = get_userid_from_name(key_user)
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "arn:aws-cn:iam::111111111111:user/" + key_user
    )
    test.test_json["detail"]["findings"][0]["Resources"][0]["Details"]["AwsIamUser"][
        "UserId"
    ] = key_user_id

    test.run()


def run_revoke_unrotated_keys(remediation, account, region):
    test = RemediationTest(remediation, account, True)

    key_user = input("Name of an IAM user: ")
    key_user_id = get_userid_from_name(key_user)
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "arn:aws-cn:iam::111111111111:user/" + key_user
    )
    test.test_json["detail"]["findings"][0]["Resources"][0]["Details"]["AwsIamUser"][
        "UserId"
    ] = key_user_id

    test.run()


def run_set_password_policy(remediation, account, region):
    print("Remediates the finding by putting in place an account password policy.\n")
    print("SETUP\n=====\n")
    print("1) Go to IAM in the console")
    print("2) Remove the target account's password policy\n")
    input("Hit enter when ready")

    test = RemediationTest(remediation, account, True)

    test.run()

    print("\nVERIFICATION\n============\n")
    print("1) Verify that the Account password policy is established")


def get_userid_from_name(username):
    aws = get_session()
    iam = aws.client("iam")
    for user in iam.list_users().get("Users", []):
        if username == user.get("UserName", ""):
            return user.get("UserId", None)
