# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# TODO: test that name over 20 characters is rejected
# TODO: test that ID over 20 characters is rejected

import os
import random

import boto3
import pytest
from action_target_provider import CustomAction, get_securityhub_client, lambda_handler
from botocore.stub import ANY, Stubber

os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_PARTITION"] = "aws"


@pytest.fixture(autouse=True)
def mock_get_account_id(mocker):
    mocker.patch("action_target_provider.get_account_id", return_value="111111111111")


class MockContext(object):
    def __init__(self, name, version):
        self.function_name = name
        self.function_version = version
        self.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:123456789012:function:{name}:{version}".format(
                name=name, version=version
            )
        )
        self.memory_limit_in_mb = float("inf")
        self.log_group_name = "test-group"
        self.log_stream_name = "test-stream"
        self.client_context = None

        self.aws_request_id = "-".join(
            [
                "".join([random.choice("0123456789abcdef") for _ in range(0, n)])
                for n in [8, 4, 4, 4, 12]
            ]
        )


context = MockContext("SO0111-SHARR-Custom-Action-Lambda", "v1.0.0")


def event(type):
    return {
        "ResourceProperties": {
            "Name": "Remediate with ASR Test",
            "Description": "Test Submit the finding to Automated Security Response on AWS",
            "Id": "ASRRemediationTest",
        },
        "RequestType": type,
        "ResponseURL": "https://bogus",
    }


def test_get_client(mocker):
    client1 = get_securityhub_client()
    assert client1
    client2 = get_securityhub_client()
    assert client2 == client1


def test_lambda_handler(mocker):
    """
    Basic check for errors
    """
    mocker.patch("action_target_provider.CustomAction.create", return_value="12341234")
    lambda_handler(event("create"), {})


def test_create(mocker):
    """
    Test that the correct API call is executed
    """
    sechub = boto3.client("securityhub")
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_response(
        "create_action_target",
        {"ActionTargetArn": "foobarbaz"},
        {
            "Name": "Remediate with ASR Test",
            "Description": " Test Submit the finding to Automated Security Response on AWS",
            "Id": "ASRRemediationTest",
        },
    )
    sechub_stub.activate()
    mocker.patch("action_target_provider.get_securityhub_client", return_value=sechub)
    mocker.patch("cfnresponse.send", return_value=None)
    lambda_handler(event("create"), {})
    sechub_stub.deactivate()


def test_create_already_exists(mocker):
    """
    Test that there is no error when it already exists
    """
    sechub = boto3.client("securityhub")
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error("create_action_target", "ResourceConflictException")
    sechub_stub.activate()
    mocker.patch("action_target_provider.get_securityhub_client", return_value=sechub)
    mocker.patch("cfnresponse.send", return_value=None)
    customAction = CustomAction(
        "111122223333",
        {
            "Name": "Remediate with ASR Test",
            "Description": "Test Submit the finding to Automated Security Response on AWS",
            "Id": "ASRRemediationTest",
        },
    )
    assert customAction.create() is None
    sechub_stub.assert_no_pending_responses()
    sechub_stub.deactivate()


def test_create_no_sechub(mocker):
    sechub = boto3.client("securityhub")
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error("create_action_target", "InvalidAccessException")
    sechub_stub.activate()
    mocker.patch("action_target_provider.get_securityhub_client", return_value=sechub)
    mocker.patch("cfnresponse.send", return_value=None)
    customAction = CustomAction(
        "111122223333",
        {
            "Name": "Remediate with ASR Test",
            "Description": "Test Submit the finding to Automated Security Response on AWS",
            "Id": "ASRRemediationTest",
        },
    )
    assert customAction.create() == "FAILED"
    sechub_stub.assert_no_pending_responses()
    sechub_stub.deactivate()


def test_create_other_client_error(mocker):
    sechub = boto3.client("securityhub")
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error("create_action_target", "ADoorIsAjar")
    sechub_stub.activate()
    mocker.patch("action_target_provider.get_securityhub_client", return_value=sechub)
    mocker.patch("cfnresponse.send", return_value=None)
    customAction = CustomAction(
        "111122223333",
        {
            "Name": "Remediate with ASR Test",
            "Description": "Test Submit the finding to Automated Security Response on AWS",
            "Id": "ASRRemediationTest",
        },
    )
    assert customAction.create() == "FAILED"
    sechub_stub.assert_no_pending_responses()
    sechub_stub.deactivate()


def test_delete(mocker):
    sechub = boto3.client("securityhub")
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_response(
        "delete_action_target",
        {"ActionTargetArn": "foobarbaz"},
        {"ActionTargetArn": ANY},
    )
    sechub_stub.activate()
    mocker.patch("action_target_provider.get_securityhub_client", return_value=sechub)
    mocker.patch("cfnresponse.send", return_value=None)
    customAction = CustomAction(
        "111122223333",
        {
            "Name": "Remediate with ASR Test",
            "Description": "Test Submit the finding to Automated Security Response on AWS",
            "Id": "ASRRemediationTest",
        },
    )
    assert customAction.delete() == "SUCCESS"
    sechub_stub.assert_no_pending_responses()
    sechub_stub.deactivate()


def test_delete_already_exists(mocker):
    sechub = boto3.client("securityhub")
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error("delete_action_target", "ResourceNotFoundException")
    sechub_stub.activate()
    mocker.patch("action_target_provider.get_securityhub_client", return_value=sechub)
    mocker.patch("cfnresponse.send", return_value=None)
    customAction = CustomAction(
        "111122223333",
        {
            "Name": "Remediate with ASR Test",
            "Description": "Test Submit the finding to Automated Security Response on AWS",
            "Id": "ASRRemediationTest",
        },
    )
    assert customAction.delete() == "SUCCESS"
    sechub_stub.deactivate()


def test_delete_no_sechub(mocker):
    sechub = boto3.client("securityhub")
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error("delete_action_target", "InvalidAccessException")
    sechub_stub.activate()
    mocker.patch("action_target_provider.get_securityhub_client", return_value=sechub)
    mocker.patch("cfnresponse.send", return_value=None)
    customAction = CustomAction(
        "111122223333",
        {
            "Name": "Remediate with ASR Test",
            "Description": "Test Submit the finding to Automated Security Response on AWS",
            "Id": "ASRRemediationTest",
        },
    )
    assert customAction.delete() == "SUCCESS"
    sechub_stub.deactivate()


def test_delete_other_client_error(mocker):
    sechub = boto3.client("securityhub")
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error("delete_action_target", "ADoorIsAjar")
    sechub_stub.activate()
    mocker.patch("action_target_provider.get_securityhub_client", return_value=sechub)
    mocker.patch("cfnresponse.send", return_value=None)
    customAction = CustomAction(
        "111122223333",
        {
            "Name": "Remediate with ASR Test",
            "Description": "Test Submit the finding to Automated Security Response on AWS",
            "Id": "ASRRemediationTest",
        },
    )
    assert customAction.delete() == "FAILED"
    sechub_stub.deactivate()


def test_customaction():
    test_object = CustomAction(
        "111122223333", {"Name": "foo", "Description": "bar", "Id": "baz"}
    )
    assert test_object.name == "foo"
    assert test_object.description == "bar"
    assert test_object.id == "baz"
    assert test_object.account == "111122223333"
