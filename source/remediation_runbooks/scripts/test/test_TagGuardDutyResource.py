# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import boto3
import botocore.session
import pytest
import TagGuardDutyResource as remediation
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
DEFAULT_TAG = "SO0111-GuardDutyResource"
mock_resource_arn = "arn:aws:guardduty:us-east-1:11111111111:detector/ecc6abbcc9780bb749aea6256c2f5676/filter/my-filter"
mock_tags = {"key1": "", "key2": ""}


@pytest.fixture
def mock_tag_guardduty_resource(mocker):
    yield mocker.patch("TagGuardDutyResource.tag_guardduty_resource", return_value=None)


def event():
    return {
        "RequiredTagKeys": ["key1", " key2"],
        "ResourceArn": mock_resource_arn,
    }


def event_with_default_tag():
    return {
        "RequiredTagKeys": [DEFAULT_TAG],
        "ResourceArn": mock_resource_arn,
    }


def setup_guardduty_stubber(mocker, should_error):
    guardduty_client = botocore.session.get_session().create_client(
        "guardduty", config=BOTO_CONFIG
    )
    guardduty_stubber = Stubber(guardduty_client)

    if should_error:
        guardduty_stubber.add_client_error(
            "tag_resource",
            service_error_code="ServiceException",
            service_message="Error",
        )
    else:
        guardduty_stubber.add_response(
            "tag_resource",
            {},
            expected_params={"ResourceArn": mock_resource_arn, "Tags": mock_tags},
        )
    mocker.patch(
        "TagGuardDutyResource.connect_to_guardduty", return_value=guardduty_client
    )
    return guardduty_stubber


def test_handler(mocker):
    guardduty_stubber = setup_guardduty_stubber(mocker, False)
    guardduty_stubber.activate()

    response = remediation.lambda_handler(event(), {})

    assert response["status"] == "Success"
    guardduty_stubber.assert_no_pending_responses()
    guardduty_stubber.deactivate()


def test_handler_with_required_tags(mock_tag_guardduty_resource):
    result = remediation.lambda_handler(event(), {})
    assert result["status"] == "Success"
    mock_tag_guardduty_resource.assert_called_once_with(
        tags=["key1", "key2"], resource_arn=mock_resource_arn
    )


def test_handler_with_exception(mocker):
    guardduty_stubber = setup_guardduty_stubber(mocker, True)
    guardduty_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.lambda_handler(event(), {})

    assert re.match(r"Failed to tag GuardDuty resource: ", str(e.value))
    guardduty_stubber.deactivate()


def test_get_required_tags_from_event():
    result = remediation.get_required_tags_from_event(event())
    assert result == ["key1", "key2"]


def test_get_default_tag_from_event():
    result = remediation.get_required_tags_from_event(event_with_default_tag())
    assert result == [DEFAULT_TAG]


def test_tag_guardduty_resource(mocker):
    guardduty_stubber = setup_guardduty_stubber(mocker, False)
    guardduty_stubber.activate()

    response = remediation.tag_guardduty_resource(
        tags=["key1", "key2"], resource_arn=mock_resource_arn
    )

    assert response is None
    guardduty_stubber.assert_no_pending_responses()
    guardduty_stubber.deactivate()
