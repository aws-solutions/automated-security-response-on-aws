# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re
from time import sleep

import boto3
import botocore.session
import pytest
import RevokeUnusedIAMUserCredentials as remediation
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws
from moto.core import set_initial_no_auth_action_count

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
TEST_USER = "Bob"


def setup(mocker):
    # Mocking config with moto requires significant setup that is out of scope for these tests,
    # so get_user_name is patched for most tests here.
    iam_client = boto3.client("iam", region_name=REGION, config=BOTO_CONFIG)
    mocker.patch("RevokeUnusedIAMUserCredentials.get_user_name", return_value=TEST_USER)
    iam_client.create_user(
        UserName=TEST_USER,
    )
    iam_client.create_login_profile(
        Password="mypassword",
        PasswordResetRequired=False,
        UserName=TEST_USER,
    )
    create_key_response = iam_client.create_access_key(
        UserName="Bob",
    )

    iam_client.attach_user_policy(
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        UserName=TEST_USER,
    )

    sleep(1)  # sleep for 1 second to ensure key creation time is > 1s

    return (
        create_key_response["AccessKey"]["AccessKeyId"],
        create_key_response["AccessKey"]["SecretAccessKey"],
    )


def setup_client_stubber(client, method, mocker):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_client_error(
        method,
        service_error_code="ServiceException",
        service_message="Error",
    )
    mocker.patch(
        "RevokeUnusedIAMUserCredentials.connect_to_service", return_value=client
    )
    return stubber


def credentials_are_deleted():
    iam_client = boto3.client("iam", region_name=REGION, config=BOTO_CONFIG)
    try:
        response = iam_client.get_user(UserName="string")
        return response["User"]
    except iam_client.exceptions.NoSuchEntityException:
        return True


@set_initial_no_auth_action_count(1)
def use_iam_credentials(access_key_id, secret_access_key):
    client = boto3.client(
        "ec2",
        region_name=REGION,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
    )

    # Arbitrary API call to use IAM creds
    response = client.describe_instances()
    return response


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_handler(mocker):
    test_access_key_id, test_secret_access_key = setup(mocker)
    use_iam_credentials(test_access_key_id, test_secret_access_key)

    response = remediation.handler(
        {"IAMResourceId": TEST_USER, "MaxCredentialUsageAge": -1}, None
    )

    assert response["Status"] == "Success"
    assert response["DeactivatedKeys"] == str([test_access_key_id])
    assert response["DeletedProfile"] == TEST_USER
    assert credentials_are_deleted()


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_handler_without_using_access_key(mocker):
    test_access_key_id, test_secret_access_key = setup(mocker)

    response = remediation.handler(
        {"IAMResourceId": TEST_USER, "MaxCredentialUsageAge": -1}, None
    )

    assert response["Status"] == "Success"
    assert response["DeactivatedKeys"] == str([test_access_key_id])
    assert response["DeletedProfile"] == TEST_USER
    assert credentials_are_deleted()


def test_get_user_name(mocker):
    test_resource_id = "iam_user_resource_id"
    client = botocore.session.get_session().create_client("config", config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_response(
        "list_discovered_resources",
        service_response={
            "resourceIdentifiers": [
                {
                    "resourceName": TEST_USER,
                },
            ],
        },
        expected_params={
            "resourceType": "AWS::IAM::User",
            "resourceIds": [test_resource_id],
        },
    )
    mocker.patch(
        "RevokeUnusedIAMUserCredentials.connect_to_service", return_value=client
    )
    stubber.activate()

    response = remediation.get_user_name(test_resource_id)

    assert response == TEST_USER
    stubber.deactivate()


def test_get_user_name_error(mocker):
    config_stubber = setup_client_stubber("config", "list_discovered_resources", mocker)
    config_stubber.activate()

    with pytest.raises(Exception) as e:
        remediation.get_user_name("my-resource-id")

    assert re.match(r"Encountered error fetching user name for resource", str(e.value))
    config_stubber.deactivate()


def test_delete_unused_password_error(mocker):
    iam_stubber = setup_client_stubber("iam", "get_user", mocker)
    iam_stubber.activate()

    with pytest.raises(Exception) as e:
        remediation.delete_unused_password(TEST_USER, 45)

    assert re.match(
        r"Encountered error deleting unused password for user", str(e.value)
    )
    iam_stubber.deactivate()


@mock_aws
def test_get_login_profile_without_existing_profile():
    iam_client = boto3.client("iam", region_name=REGION, config=BOTO_CONFIG)
    iam_client.create_user(
        UserName=TEST_USER,
    )
    response = remediation.get_login_profile(TEST_USER)

    assert response is None


def test_deactivate_unused_keys_error(mocker):
    iam_stubber = setup_client_stubber("iam", "get_access_key_last_used", mocker)
    iam_stubber.activate()

    with pytest.raises(Exception) as e:
        remediation.deactivate_unused_keys(["my-key"], 45, TEST_USER)

    assert re.match(r"Encountered error deactivating unused access keys:", str(e.value))
    iam_stubber.deactivate()


@mock_aws
def test_deactivate_key_client_error():
    response = remediation.deactivate_key(TEST_USER, "thiskeyissixteenchars")

    assert response is None


def test_deactivate_key_general_error(mocker):
    iam_stubber = setup_client_stubber("iam", "update_access_key", mocker)
    iam_stubber.activate()

    with pytest.raises(Exception) as e:
        remediation.deactivate_key(TEST_USER, "my-key")

    assert re.match(r"Encountered error deactivating access key", str(e.value))
    iam_stubber.deactivate()


def test_list_access_keys_error(mocker):
    iam_stubber = setup_client_stubber("iam", "list_access_keys", mocker)
    iam_stubber.activate()

    with pytest.raises(Exception) as e:
        remediation.list_access_keys(TEST_USER)

    assert re.match(r"Encountered error listing access keys for user", str(e.value))
    iam_stubber.deactivate()


def test_handler_with_invalid_event():
    with pytest.raises(Exception) as e:
        remediation.handler(
            {
                "InvalidKey": "test_value",
            },
            None,
        )
    assert re.match(
        r"Encountered error while revoking unusued IAM user credentials: ", str(e.value)
    )
