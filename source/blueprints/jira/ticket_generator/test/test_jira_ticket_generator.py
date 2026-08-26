# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import re
import urllib.error
import uuid
from unittest.mock import MagicMock, patch

import boto3
from aws_lambda_context import LambdaContext
from botocore.config import Config
from jira_ticket_generator import (
    APICredentials,
    RemediationInfo,
    create_ticket,
    get_account_alias,
    get_api_credentials,
    get_current_user_account_id,
    get_post_endpoint_from_instance_uri,
    lambda_handler,
)
from moto import mock_aws

REGION = "us-east-1"
FAKE_API_CREDENTIALS = {"Username": "my-username", "Password": "my-password"}
FAKE_INSTANCE_URI = "https://my-instance.atlassian.net"
FAKE_JIRA_ENDPOINT = f"{FAKE_INSTANCE_URI}/rest/api/2/issue"
MOTO_ACCOUNT_ID = "123456789012"

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup():
    client = boto3.client("secretsmanager", config=BOTO_CONFIG)
    response = client.create_secret(
        Name="my_new_secret",
        SecretString=json.dumps(FAKE_API_CREDENTIALS),
    )

    client = boto3.client("organizations", region_name="us-east-1")
    client.create_organization(FeatureSet="ALL")

    os.environ["SECRET_ARN"] = response["ARN"]
    os.environ["INSTANCE_URI"] = FAKE_INSTANCE_URI
    os.environ["PROJECT_NAME"] = "MP"
    os.environ["JIRA_FIELDS_MAPPING"] = json.dumps(
        {
            "reporter": {"accountId": f"123456:{uuid.uuid4()}"},
            "priority": {"id": "3"},
            "issuetype": {"id": "10006"},
        }
    )


def setup_lambda_context():
    lambda_context = LambdaContext()
    lambda_context.function_name = "function_name"
    lambda_context.function_version = "function_version"
    lambda_context.invoked_function_arn = "invoked_function_arn"
    lambda_context.memory_limit_in_mb = 2
    lambda_context.aws_request_id = "aws_request_id"
    lambda_context.log_group_name = "log_group_name"
    lambda_context.log_stream_name = "log_stream_name"
    return lambda_context


@patch("urllib.request.urlopen")
@mock_aws
def test_ticket_generator(mock_urlopen):
    # ARRANGE
    setup()
    lambda_context = setup_lambda_context()

    def mock_urlopen_side_effect(request, timeout=None):
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.getcode.return_value = 201
        mock_response.read.return_value = json.dumps({"key": "my-ticket-id"}).encode(
            "utf-8"
        )
        return mock_response

    mock_urlopen.side_effect = mock_urlopen_side_effect

    # ACT
    response = lambda_handler(
        {
            "RemediationInfo": {
                "Message": "my message",
                "FindingDescription": "this is a finding",
                "FindingSeverity": "LOW",
                "SecurityControlId": "foobar.1",
                "FindingAccountId": MOTO_ACCOUNT_ID,
                "AffectedResource": "my-s3-bucket",
            },
        },
        lambda_context,
    )

    # ASSERT
    assert response["ResponseCode"] == "201"
    assert (
        response["TicketURL"] == "https://my-instance.atlassian.net/browse/my-ticket-id"
    )
    assert response["Ok"]


@patch("urllib.request.urlopen")
@mock_aws
def test_ticket_generator_jira_error(mock_urlopen):
    # ARRANGE
    setup()
    lambda_context = setup_lambda_context()

    def mock_urlopen_side_effect(request, timeout=None):
        raise urllib.error.HTTPError(
            FAKE_JIRA_ENDPOINT, 400, "Bad Request", {}, None  # type: ignore
        )

    mock_urlopen.side_effect = mock_urlopen_side_effect

    # ACT
    response = lambda_handler(
        {
            "RemediationInfo": {
                "Message": "my message",
                "FindingDescription": "this is a finding",
                "FindingSeverity": "LOW",
                "SecurityControlId": "foobar.1",
                "FindingAccountId": MOTO_ACCOUNT_ID,
                "AffectedResource": "my-s3-bucket",
            },
        },
        lambda_context,
    )

    # ASSERT
    assert not response["Ok"]
    assert response["ResponseCode"] == "400"
    assert response["ResponseReason"] == "Bad Request"


@mock_aws
def test_ticket_generator_without_secret():
    # ARRANGE
    lambda_context = setup_lambda_context()
    os.environ["SECRET_ARN"] = "my-secret-arn"

    # ACT
    response = lambda_handler(
        {
            "RemediationInfo": {
                "Message": "my message",
                "FindingDescription": "this is a finding",
                "FindingSeverity": "LOW",
                "SecurityControlId": "foobar.1",
                "FindingAccountId": MOTO_ACCOUNT_ID,
                "AffectedResource": "my-s3-bucket",
            },
        },
        lambda_context,
    )

    # ASSERT
    assert not response["Ok"]
    assert response["ResponseCode"] == "Error"
    assert re.search(
        r"Could not retrieve value stored in secret ", response["ResponseReason"]
    )


def test_ticket_generator_with_invalid_uri():
    # ARRANGE
    lambda_context = setup_lambda_context()
    os.environ["INSTANCE_URI"] = "https://example.com"
    os.environ["PROJECT_NAME"] = "MP"

    # ACT
    response = lambda_handler(
        {
            "RemediationInfo": {
                "Message": "my message",
                "FindingDescription": "this is a finding",
                "FindingSeverity": "LOW",
                "SecurityControlId": "foobar.1",
                "FindingAccountId": MOTO_ACCOUNT_ID,
                "AffectedResource": "my-s3-bucket",
            },
        },
        lambda_context,
    )

    # ASSERT
    assert not response["Ok"]
    assert response["ResponseCode"] == "Error"
    assert re.search(
        r"Jira Instance URI https://example.com does not match expected structure",
        response["ResponseReason"],
    )


@mock_aws
def test_get_account_alias():
    client = boto3.client("organizations", region_name="us-east-1")
    client.create_organization(FeatureSet="ALL")

    account_alias = get_account_alias(MOTO_ACCOUNT_ID)

    assert account_alias == "master"


@mock_aws
def test_get_account_alias_error():
    account_alias = get_account_alias(MOTO_ACCOUNT_ID)

    assert account_alias == MOTO_ACCOUNT_ID


def test_get_post_endpoint_from_instance_uri():
    # ACT
    result = get_post_endpoint_from_instance_uri("https://test.atlassian.net")

    # ASSERT
    assert result == "https://test.atlassian.net/rest/api/2/issue"


def test_get_post_endpoint_invalid_uri():
    # ACT & ASSERT
    try:
        get_post_endpoint_from_instance_uri("https://invalid.com")
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass


@patch("jira_ticket_generator.get_secret_value_cached")
def test_get_api_credentials(mock_get_secret):
    # ARRANGE
    mock_get_secret.return_value = '{"Username": "user", "Password": "pass"}'

    # ACT
    result = get_api_credentials("test-arn")

    # ASSERT
    assert result["Username"] == "user"
    assert result["Password"] == "pass"


@patch("jira_ticket_generator.get_secret_value_cached")
def test_get_api_credentials_missing_keys(mock_get_secret):
    # ARRANGE
    mock_get_secret.return_value = '{"Username": "user"}'

    # ACT & ASSERT
    try:
        get_api_credentials("test-arn")
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass


@patch("jira_ticket_generator.connect_to_service")
def test_get_account_alias_with_connect_mock(mock_connect):
    # ARRANGE
    mock_org = MagicMock()
    mock_org.describe_account.return_value = {"Account": {"Name": "TestAccount"}}
    mock_connect.return_value = mock_org

    # ACT
    result = get_account_alias("123456789012")

    # ASSERT
    assert result == "TestAccount"


@patch("jira_ticket_generator.connect_to_service")
def test_get_account_alias_error_with_connect_mock(mock_connect):
    # ARRANGE
    mock_connect.side_effect = Exception("Error")

    # ACT
    result = get_account_alias("123456789012")

    # ASSERT
    assert result == "123456789012"


@patch("urllib.request.urlopen")
def test_create_ticket_success(mock_urlopen):
    # ARRANGE
    import jira_ticket_generator

    jira_ticket_generator._cached_jira_account_id = ""  # Reset cache

    def mock_urlopen_side_effect(request, timeout=None):
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        if "/myself" in str(request.full_url):
            mock_response.getcode.return_value = 200
            mock_response.read.return_value = json.dumps(
                {"accountId": "test-account-id"}
            ).encode("utf-8")
        else:
            mock_response.getcode.return_value = 201
            mock_response.read.return_value = json.dumps({"key": "TEST-123"}).encode(
                "utf-8"
            )
        return mock_response

    mock_urlopen.side_effect = mock_urlopen_side_effect

    remediation_info: RemediationInfo = {
        "Message": "Test",
        "FindingDescription": "Test",
        "FindingSeverity": "HIGH",
        "SecurityControlId": "TEST.1",
        "FindingAccountId": "123456789012",
        "AffectedResource": "test",
    }
    api_credentials: APICredentials = {"Username": "user", "Password": "pass"}

    # ACT
    result = create_ticket(
        remediation_info,
        "https://test.atlassian.net",
        "https://test.atlassian.net/rest/api/2/issue",
        api_credentials,
        "TEST",
        "TestAccount",
    )

    # ASSERT
    assert result["Ok"] is True
    assert "TEST-123" in result["TicketURL"]


@patch("urllib.request.urlopen")
def test_get_current_user_account_id_success(mock_urlopen):
    # ARRANGE
    import jira_ticket_generator

    jira_ticket_generator._cached_jira_account_id = ""  # Reset cache

    def mock_urlopen_side_effect(request, timeout=None):
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.read.return_value = json.dumps(
            {"accountId": "test-account-id"}
        ).encode("utf-8")
        return mock_response

    mock_urlopen.side_effect = mock_urlopen_side_effect
    api_credentials: APICredentials = {"Username": "user", "Password": "pass"}

    # ACT
    result = get_current_user_account_id("https://test.atlassian.net", api_credentials)

    # ASSERT
    assert result == "test-account-id"
    assert mock_urlopen.call_count == 1

    # Test cache hit
    result2 = get_current_user_account_id("https://test.atlassian.net", api_credentials)
    assert result2 == "test-account-id"
    assert mock_urlopen.call_count == 1  # No additional call


@patch("urllib.request.urlopen")
def test_get_current_user_account_id_error(mock_urlopen):
    # ARRANGE
    import jira_ticket_generator

    jira_ticket_generator._cached_jira_account_id = ""  # Reset cache
    mock_urlopen.side_effect = Exception("API Error")
    api_credentials: APICredentials = {"Username": "user", "Password": "pass"}

    # ACT
    result = get_current_user_account_id("https://test.atlassian.net", api_credentials)

    # ASSERT
    assert result == ""
