# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


def connect_to_service(service):
    return boto3.client(service, config=boto_config)


class Event(TypedDict):
    AllowUsersToChangePassword: bool
    HardExpiry: bool
    MaxPasswordAge: int
    MinimumPasswordLength: int
    PasswordReusePrevention: int
    RequireLowercaseCharacters: bool
    RequireNumbers: bool
    RequireSymbols: bool
    RequireUppercaseCharacters: bool


class Response(TypedDict):
    Status: str
    Message: str
    PasswordPolicy: Event


def set_iam_password_policy(event: Event, _) -> Response:
    iam_client = connect_to_service("iam")
    try:
        iam_client.update_account_password_policy(**event)
        return {
            "Status": "Success",
            "Message": "IAM user password policy updated successfully",
            "PasswordPolicy": event,
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error while updating IAM user password policy: {str(e)}"
        )
