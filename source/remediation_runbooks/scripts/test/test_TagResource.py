# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import boto3
import pytest
import TagResource as remediation
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

my_session = boto3.session.Session()
my_region = my_session.region_name

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=REGION)
DEFAULT_TAG = "SO0111-GuardDutyResource"
mock_resource_arn = "arn:aws:guardduty:us-east-1:11111111111:detector/ecc6abbcc9780bb749aea6256c2f5676/filter/my-filter"
mock_tags = {"key1": "", "key2": ""}


def setup_dynamodb():
    client = boto3.client("dynamodb", config=BOTO_CONFIG)
    response = client.create_table(
        AttributeDefinitions=[
            {
                "AttributeName": "Artist",
                "AttributeType": "S",
            },
            {
                "AttributeName": "SongTitle",
                "AttributeType": "S",
            },
        ],
        KeySchema=[
            {
                "AttributeName": "Artist",
                "KeyType": "HASH",
            },
            {
                "AttributeName": "SongTitle",
                "KeyType": "RANGE",
            },
        ],
        ProvisionedThroughput={
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5,
        },
        TableName="Music",
    )

    return response["TableDescription"]["TableName"]


def dynamodb_table_has_tags(table_arn, required_tags):
    client = boto3.client("dynamodb", config=BOTO_CONFIG)
    response = client.list_tags_of_resource(ResourceArn=table_arn)

    tag_keys = {tag["Key"] for tag in response.get("Tags", [])}

    missing_tags = set(required_tags) - tag_keys

    if missing_tags:
        print(f"Missing required tags: {missing_tags}")
        return False

    return True


def guardduty_event():
    return {"RequiredTagKeys": ["key1", "key2"], "ResourceType": "GuardDuty"}


def dynamodb_event():
    return {"RequiredTagKeys": ["key1", "key2"], "ResourceType": "DynamoDBTable"}


def bad_event():
    return {"RequiredTagKeys": ["key1", "key2"], "ResourceType": "GuardDuty"}


@mock_aws
def test_handler_dynamodb(mocker):
    table_name = setup_dynamodb()
    event = dynamodb_event()
    event["ResourceArn"] = f"arn:aws:dynamodb:{REGION}:123456789012:table/{table_name}"

    response = remediation.lambda_handler(event, {})

    assert response["status"] == "Success"
    assert dynamodb_table_has_tags(event["ResourceArn"], event["RequiredTagKeys"])


@mock_aws
def test_handler_with_exception(mocker):
    with pytest.raises(Exception) as e:
        remediation.lambda_handler(bad_event(), {})

    assert re.match(r"Failed to tag resource: ", str(e.value))


# Moto does not currently (3/24/25) support the guardduty.tag_resource API
# hence, we must Stub the call using botocore directly.
def test_handler_guardduty(mocker):
    guardduty_client = boto3.client("guardduty", region_name=REGION)
    stubber = Stubber(guardduty_client)
    mocker.patch("TagResource.get_guardduty_client", return_value=guardduty_client)

    # Mock data
    detector_id = "detector123"
    filter_name = "test-filter"
    resource_arn = f"arn:aws:guardduty:us-east-1:123456789012:detector/{detector_id}/filter/{filter_name}"
    tags = {"Tag1": "", "Tag2": ""}

    stubber.add_response(
        "tag_resource", {}, {"ResourceArn": resource_arn, "Tags": tags}
    )
    stubber.activate()

    remediation.lambda_handler(
        {
            "ResourceArn": resource_arn,
            "RequiredTagKeys": list(tags.keys()),
            "ResourceType": "GuardDuty",
        },
        {},
    )

    stubber.assert_no_pending_responses()
    stubber.deactivate()
