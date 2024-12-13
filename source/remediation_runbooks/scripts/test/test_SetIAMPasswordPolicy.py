# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import boto3
import botocore.session
import pytest
import SetIAMPasswordPolicy as remediation
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
TEST_IAM_PASSWORD_POLICY = {
    "AllowUsersToChangePassword": False,
    "HardExpiry": True,
    "MaxPasswordAge": 5,
    "MinimumPasswordLength": 6,
    "PasswordReusePrevention": 1,
    "RequireLowercaseCharacters": True,
    "RequireNumbers": True,
    "RequireSymbols": True,
    "RequireUppercaseCharacters": True,
}


def setup_client_stubber(client, method, mocker):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_client_error(
        method,
        service_error_code="ServiceException",
        service_message="Error",
    )
    mocker.patch("SetIAMPasswordPolicy.connect_to_service", return_value=client)
    return stubber


def verify_password_policy(expected_policy):
    iam_client = boto3.client("iam", config=BOTO_CONFIG, region_name=REGION)
    response = iam_client.get_account_password_policy()
    actual_policy = response["PasswordPolicy"]
    return all(
        [actual_policy[key] == expected_policy[key] for key in expected_policy.keys()]
    )


@mock_aws
def test_set_iam_password_policy():
    response = remediation.set_iam_password_policy(TEST_IAM_PASSWORD_POLICY, None)

    assert response["Status"] == "Success"
    assert verify_password_policy(TEST_IAM_PASSWORD_POLICY)


def test_set_iam_password_policy_with_client_error(mocker):
    iam_stubber = setup_client_stubber("iam", "update_account_password_policy", mocker)

    iam_stubber.activate()
    with pytest.raises(RuntimeError) as e:
        remediation.set_iam_password_policy(TEST_IAM_PASSWORD_POLICY, None)

    assert re.match(
        r"Encountered error while updating IAM user password policy:", str(e.value)
    )
    iam_stubber.deactivate()
