# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# TODO: test that name over 20 characters is rejected
# TODO: test that ID over 20 characters is rejected

import os
import random

import boto3
import pytest
from action_target_provider import (
    CustomAction,
    InvalidCustomAction,
    get_account_id,
    get_securityhub_client,
    lambda_handler,
)
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
    Test that the ARN is retrieved when it already exists
    """
    sechub = boto3.client("securityhub")
    sechub_stub = Stubber(sechub)
    # Note: boto mock appears to be broken for the Sec Hub API
    # It only works if the response containts "ActionTargetArn"
    sechub_stub.add_client_error("create_action_target", "ResourceConflictException")
    sechub_stub.add_response(
        "describe_action_targets",
        {
            "ActionTargets": [
                {
                    "Name": "Remediate with ASR Test",
                    "Description": " Test Submit the finding to Automated Security Response on AWS",
                    "ActionTargetArn": "arn:aws:us-east-1:my-action-target-arn",
                },
            ]
        },
        {},
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
    assert customAction.create() == "arn:aws:us-east-1:my-action-target-arn"
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


def test_invalid_custom_action_missing_fields():
    with pytest.raises(InvalidCustomAction):
        CustomAction("111122223333", {"Name": "", "Description": "desc", "Id": "id"})


def test_get_handles_exception(mocker):
    client = mocker.Mock()
    client.get_paginator.side_effect = Exception("boom")
    mocker.patch("action_target_provider.get_securityhub_client", return_value=client)
    custom_action = CustomAction(
        "111122223333", {"Name": "n", "Description": "d", "Id": "i"}
    )
    assert custom_action.get() == "FAILED"


def test_delete_general_exception(mocker):
    client = mocker.Mock()
    client.delete_action_target.side_effect = ValueError("boom")
    mocker.patch("action_target_provider.get_securityhub_client", return_value=client)
    custom_action = CustomAction(
        "111122223333", {"Name": "n", "Description": "d", "Id": "i"}
    )
    assert custom_action.delete() == "FAILED"


def test_get_account_id_calls_sts(mocker):
    # `get_account_id` is imported by reference above, so the autouse patch of the
    # module attribute does not shadow it here — this exercises the real STS call.
    mock_sts = mocker.Mock()
    mock_sts.get_caller_identity.return_value = {"Account": "999988887777"}
    mocker.patch("action_target_provider.boto3.client", return_value=mock_sts)
    assert get_account_id() == "999988887777"


def test_lambda_handler_swallows_exception(mocker):
    mocker.patch("action_target_provider.CustomAction.create", return_value="arn")
    mocker.patch("cfnresponse.send", return_value=None)
    # Missing RequestType raises KeyError inside the handler body; the outer
    # except must catch and log it without re-raising.
    bad_event = {
        "ResourceProperties": {"Name": "n", "Description": "d", "Id": "i"},
    }
    lambda_handler(bad_event, {})


def test_lambda_handler_delete(mocker):
    mocker.patch("action_target_provider.CustomAction.delete", return_value="SUCCESS")
    mocker.patch("cfnresponse.send", return_value=None)
    lambda_handler(event("Delete"), {})


def test_lambda_handler_invalid_request_type(mocker):
    mocker.patch("cfnresponse.send", return_value=None)
    lambda_handler(event("Bogus"), {})
