# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_lambda(boto_config):
    return boto3.client("lambda", config=boto_config)


def print_policy_before(policy):
    print("Resource Policy to be deleted:")
    print(json.dumps(policy, indent=2, default=str))


def public_s3_statement_check(statement, principal):
    """
    This function checks if the user has given access to an S3 bucket without providing an AWS account.
    """
    try:
        empty_source_account_check = False
        if "StringEquals" in statement["Condition"]:
            empty_source_account_check = (
                "AWS:SourceAccount" not in statement["Condition"]["StringEquals"]
            )
        else:
            empty_source_account_check = True
        return (
            principal.get("Service", "") == "s3.amazonaws.com"
            and empty_source_account_check
        )
    except KeyError:
        return principal.get("Service", "") == "s3.amazonaws.com"


def remove_resource_policy(functionname, sid, client):
    try:
        client.remove_permission(FunctionName=functionname, StatementId=sid)
        print(f"SID {sid} removed from Lambda function {functionname}")
    except Exception as e:
        exit(
            f"FAILED: SID {sid} was NOT removed from Lambda function {functionname} - {str(e)}"
        )


def remove_public_statement(client, functionname, statement, principal):
    if principal == "*" or (
        isinstance(principal, dict)
        and (
            principal.get("AWS", "") == "*"
            or public_s3_statement_check(statement, principal)
        )
    ):
        print_policy_before(statement)
        remove_resource_policy(functionname, statement["Sid"], client)


def remove_lambda_public_access(event, _):
    client = connect_to_lambda(boto_config)

    functionname = event["FunctionName"]
    try:
        response = client.get_policy(FunctionName=functionname)
        policy = response["Policy"]
        policy_json = json.loads(policy)
        statements = policy_json["Statement"]

        print("Scanning for public resource policies in " + functionname)

        for statement in statements:
            remove_public_statement(
                client, functionname, statement, statement["Principal"]
            )

        client.get_policy(FunctionName=functionname)

        verify(functionname)
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        if exception_type in ["ResourceNotFoundException"]:
            print("Remediation completed. Resource policy is now empty.")
        else:
            exit(f"ERROR: Remediation failed for RemoveLambdaPublicAccess: {str(ex)}")
    except Exception as e:
        exit(f"ERROR: Remediation failed for RemoveLambdaPublicAccess: {str(e)}")


def verify(function_name_to_check):
    client = connect_to_lambda(boto_config)

    try:
        response = client.get_policy(FunctionName=function_name_to_check)

        print("Remediation executed successfully. Policy after:")
        print(json.dumps(response, indent=2, default=str))

    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        if exception_type in ["ResourceNotFoundException"]:
            print("Remediation completed. Resource policy is now empty.")
        else:
            exit(f"ERROR: {exception_type} on get_policy")
    except Exception as e:
        exit(f"Exception while retrieving lambda function policy: {str(e)}")
