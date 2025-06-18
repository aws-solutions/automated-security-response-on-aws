# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from botocore.exceptions import ClientError

from simtest.boto_session import get_session
from simtest.remediation_test import RemediationTest


def run_make_lambda_private(remediation, account, region):
    aws = get_session()
    print("This test removes public permissions to Lambdas.\n")

    print("WARNING: This test may result in a Sev 2!\n")
    input("Press ENTER to confirm that you read the warning.")

    lambda_name = None
    if account == aws.get_account():
        print("Automatic Setup\n")
        print("===============\n")
        print(
            '1) Create a lambda in the test account using the "Hello, world!" example code.'
        )
        lambda_name = input("Lambda function name: ")

        make_lambda_public(lambda_name)
    else:
        print("Manual Setup\n")
        print("===============\n")
        print(
            '1) Create a lambda in the test account using the "Hello, world!" example code.'
        )
        print(
            "2) Make the lambda public by running the following CLI in the target account:"
        )
        print(
            "  aws lambda add-permission --function-name <name> --statement-id SHARRTest --action lambda:InvokeFunction --principal '*'"
        )
        lambda_name = input("Enter the name of the test lambda: ")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "AWS::::Account:" + account
    )
    test.test_json["detail"]["findings"][0]["Resources"][0]["Details"][
        "AwsLambdaFunction"
    ]["FunctionName"] = lambda_name
    test.run()

    print("\nVERIFICATION\n============\n")
    print(f"1) {lambda_name} is no longer public")


def make_lambda_public(functionname):
    """
    This will result in a sev 2, so know what you are doing!
    """
    aws = get_session()
    lmb = aws.client("lambda")
    try:
        lmb.add_permission(
            FunctionName=functionname,
            StatementId="SHARRTest",
            Action="lambda:InvokeFunction",
            Principal="*",
        )
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # stream did exist but need new token, get it from exception data
        if exception_type == "ResourceNotFoundException":
            print(f"{functionname} does not exist.")
            exit()
        else:
            print(f"Unhandled client error {exception_type}")
            raise
    except Exception as e:
        print(e)
        print("Something went wrong")
        raise
