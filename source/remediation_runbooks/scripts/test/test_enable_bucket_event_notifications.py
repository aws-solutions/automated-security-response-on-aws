# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `enable_bucket_event_notifications` remediation script"""

import json

import boto3
import pytest
from enable_bucket_event_notifications import lambda_handler
from moto import mock_aws

bucket_name = "test-bucket"
topic_name = "testTopic"
account_id = "111111111"
event_types = [
    "s3:ReducedRedundancyLostObject",
    "s3:ObjectCreated:*",
    "s3:ObjectRemoved:*",
    "s3:ObjectRestore:*",
    "s3:Replication:*",
    "s3:LifecycleExpiration:*",
    "s3:LifecycleTransition",
    "s3:IntelligentTiering",
    "s3:ObjectTagging:*",
    "s3:ObjectAcl:Put",
]
region = "us-east-1"


@mock_aws
def test_enable_bucket_event_notifications():
    sns = boto3.client("sns", region_name=region)
    s3 = boto3.client("s3", region_name=region)

    # Create S3 bucket
    s3.create_bucket(Bucket=bucket_name)

    # Create SNS topic
    topic_response = sns.create_topic(Name=topic_name)
    topic_arn = topic_response["TopicArn"]

    event = {
        "bucket_name": bucket_name,
        "topic_name": topic_name,
        "account_id": account_id,
        "event_types": event_types,
    }
    response = lambda_handler(event, {})

    assert response == {"NotificationARNs": topic_arn, "resource_arn": topic_arn}
    assert response["resource_arn"] == topic_arn

    # Verify bucket notification configuration
    config = s3.get_bucket_notification_configuration(Bucket=bucket_name)
    assert "TopicConfigurations" in config
    assert len(config["TopicConfigurations"]) == 1
    assert config["TopicConfigurations"][0]["TopicArn"] == topic_arn


@mock_aws
def test_enable_bucket_event_notifications_topic_exists():
    sns = boto3.client("sns", region_name=region)
    s3 = boto3.client("s3", region_name=region)

    # Create S3 bucket
    s3.create_bucket(Bucket=bucket_name)

    # Create SNS topic with existing policy
    topic_response = sns.create_topic(Name=topic_name)
    topic_arn = topic_response["TopicArn"]

    # Set topic attributes with existing policy
    existing_policy = {
        "Version": "2012-10-17",
        "Id": "ASR Notification Policy",
        "Statement": [
            {
                "Sid": "test-bucket ASR Notification Policy",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": "111111111111"},
                    "ArnLike": {"aws:SourceArn": "arn:aws:s3:::test1"},
                },
            }
        ],
    }
    import json

    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(existing_policy),
    )

    event = {
        "bucket_name": bucket_name,
        "topic_name": topic_name,
        "account_id": account_id,
        "event_types": event_types,
    }
    response = lambda_handler(event, {})

    assert response == {"NotificationARNs": topic_arn, "resource_arn": topic_arn}
    assert response["resource_arn"] == topic_arn

    # Verify bucket notification configuration
    config = s3.get_bucket_notification_configuration(Bucket=bucket_name)
    assert "TopicConfigurations" in config
    assert len(config["TopicConfigurations"]) == 1
    assert config["TopicConfigurations"][0]["TopicArn"] == topic_arn


@mock_aws
def test_enable_bucket_event_notifications_topic_exists_sid_exists():
    sns = boto3.client("sns", region_name=region)
    s3 = boto3.client("s3", region_name=region)

    # Create S3 bucket
    s3.create_bucket(Bucket=bucket_name)

    # Create SNS topic with existing policy that has a different SID
    topic_response = sns.create_topic(Name=topic_name)
    topic_arn = topic_response["TopicArn"]

    # Set topic attributes with existing policy (different SID)
    existing_policy = {
        "Version": "2012-10-17",
        "Id": "ASR Notification Policy",
        "Statement": [
            {
                "Sid": "ASR Notification Policy",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": "111111111111"},
                    "ArnLike": {"aws:SourceArn": "arn:aws:s3:::test1"},
                },
            }
        ],
    }
    import json

    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(existing_policy),
    )

    event = {
        "bucket_name": bucket_name,
        "topic_name": topic_name,
        "account_id": account_id,
        "event_types": event_types,
    }
    response = lambda_handler(event, {})

    assert response == {"NotificationARNs": topic_arn, "resource_arn": topic_arn}
    assert response["resource_arn"] == topic_arn

    # Verify bucket notification configuration
    config = s3.get_bucket_notification_configuration(Bucket=bucket_name)
    assert "TopicConfigurations" in config
    assert len(config["TopicConfigurations"]) == 1
    assert config["TopicConfigurations"][0]["TopicArn"] == topic_arn


@mock_aws
def test_assert_bucket_notifications_configured_raises_error_when_notifications_missing():
    sns = boto3.client("sns", region_name=region)
    s3 = boto3.client("s3", region_name=region)

    # Create S3 bucket
    s3.create_bucket(Bucket=bucket_name)

    # Create SNS topic
    sns.create_topic(Name=topic_name)

    event = {
        "bucket_name": bucket_name,
        "topic_name": topic_name,
        "account_id": account_id,
        "event_types": event_types,
    }

    # Call lambda_handler which will configure notifications
    lambda_handler(event, {})

    # Now manually clear the notification configuration to simulate error case
    s3.put_bucket_notification_configuration(
        Bucket=bucket_name, NotificationConfiguration={}
    )

    # Verify that calling assert_bucket_notifcations_configured raises an error
    from enable_bucket_event_notifications import assert_bucket_notifcations_configured

    with pytest.raises(
        RuntimeError,
        match=f"ERROR: {bucket_name} was not configured with notifications",
    ):
        assert_bucket_notifcations_configured(bucket_name, account_id)


@mock_aws
def test_enable_bucket_event_notifications_consolidates_policy():
    """Multiple buckets share one constant statement that does not list bucket ARNs."""
    sns = boto3.client("sns", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    test_account = "123456789012"  # moto default account

    s3.create_bucket(Bucket="bucket-a")
    s3.create_bucket(Bucket="bucket-b")
    sns.create_topic(Name=topic_name)

    # First bucket
    lambda_handler(
        {
            "bucket_name": "bucket-a",
            "topic_name": topic_name,
            "account_id": test_account,
            "event_types": event_types,
        },
        {},
    )
    # Second bucket
    lambda_handler(
        {
            "bucket_name": "bucket-b",
            "topic_name": topic_name,
            "account_id": test_account,
            "event_types": event_types,
        },
        {},
    )

    # Verify consolidated policy
    topic_arn = f"arn:aws:sns:{region}:{test_account}:{topic_name}"
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)
    policy = json.loads(attrs["Attributes"]["Policy"])

    # Should have exactly one consolidated statement scoped by account, not per bucket
    consolidated = [
        s for s in policy["Statement"] if s.get("Sid") == "ASR S3 Notification Policy"
    ]
    assert len(consolidated) == 1
    condition = consolidated[0]["Condition"]
    # Constant wildcard SourceArn — individual bucket ARNs are NOT listed
    assert condition["ArnLike"]["aws:SourceArn"] == "arn:aws:s3:::*"
    assert condition["StringEquals"]["aws:SourceAccount"] == test_account
    assert "arn:aws:s3:::bucket-a" not in json.dumps(consolidated[0])
    assert "arn:aws:s3:::bucket-b" not in json.dumps(consolidated[0])


@mock_aws
def test_enable_bucket_event_notifications_policy_size_is_constant():
    """The policy size must not grow as more buckets are remediated."""
    sns = boto3.client("sns", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    test_account = "123456789012"

    sns.create_topic(Name=topic_name)
    topic_arn = f"arn:aws:sns:{region}:{test_account}:{topic_name}"

    def policy_size() -> int:
        attrs = sns.get_topic_attributes(TopicArn=topic_arn)
        return len(attrs["Attributes"]["Policy"].encode("utf-8"))

    sizes = []
    for index in range(5):
        bucket = f"bucket-{index}"
        s3.create_bucket(Bucket=bucket)
        lambda_handler(
            {
                "bucket_name": bucket,
                "topic_name": topic_name,
                "account_id": test_account,
                "event_types": event_types,
            },
            {},
        )
        sizes.append(policy_size())

    # Every remediation leaves the policy at the same fixed size
    assert len(set(sizes)) == 1


@mock_aws
def test_enable_bucket_event_notifications_idempotent():
    """Test that calling twice for the same bucket doesn't duplicate statements."""
    sns = boto3.client("sns", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    test_account = "123456789012"

    s3.create_bucket(Bucket=bucket_name)
    sns.create_topic(Name=topic_name)

    event = {
        "bucket_name": bucket_name,
        "topic_name": topic_name,
        "account_id": test_account,
        "event_types": event_types,
    }
    lambda_handler(event, {})
    lambda_handler(event, {})

    topic_arn = f"arn:aws:sns:{region}:{test_account}:{topic_name}"
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)
    policy = json.loads(attrs["Attributes"]["Policy"])

    consolidated = [
        s for s in policy["Statement"] if s.get("Sid") == "ASR S3 Notification Policy"
    ]
    # Exactly one consolidated statement even after repeated runs
    assert len(consolidated) == 1


@mock_aws
def test_enable_bucket_event_notifications_upgrades_legacy_statement():
    """A legacy per-bucket-ARN consolidated statement is upgraded to the constant form."""
    sns = boto3.client("sns", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    test_account = "123456789012"

    s3.create_bucket(Bucket=bucket_name)
    topic_response = sns.create_topic(Name=topic_name)
    topic_arn = topic_response["TopicArn"]

    # Legacy consolidated statement that lists an explicit bucket ARN
    legacy_policy = {
        "Version": "2012-10-17",
        "Id": "ASR Notification Policy",
        "Statement": [
            {
                "Sid": "ASR S3 Notification Policy",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": ["SNS:Publish"],
                "Resource": topic_arn,
                "Condition": {
                    "ArnLike": {"aws:SourceArn": ["arn:aws:s3:::legacy-bucket"]},
                    "StringEquals": {"aws:SourceAccount": [test_account]},
                },
            }
        ],
    }
    sns.set_topic_attributes(
        TopicArn=topic_arn,
        AttributeName="Policy",
        AttributeValue=json.dumps(legacy_policy),
    )

    event = {
        "bucket_name": bucket_name,
        "topic_name": topic_name,
        "account_id": test_account,
        "event_types": event_types,
    }
    result = lambda_handler(event, {})

    assert result["resource_arn"] == topic_arn
    attrs = sns.get_topic_attributes(TopicArn=topic_arn)
    policy = json.loads(attrs["Attributes"]["Policy"])
    consolidated = [
        s for s in policy["Statement"] if s.get("Sid") == "ASR S3 Notification Policy"
    ]
    # Legacy statement is replaced in place with the constant wildcard form
    assert len(consolidated) == 1
    assert consolidated[0]["Condition"]["ArnLike"]["aws:SourceArn"] == "arn:aws:s3:::*"
    assert "arn:aws:s3:::legacy-bucket" not in json.dumps(policy)


@pytest.mark.parametrize(
    "region_name, expected_partition",
    [
        ("us-gov-west-1", "aws-us-gov"),
        ("us-gov-east-1", "aws-us-gov"),
        ("cn-north-1", "aws-cn"),
        ("cn-northwest-1", "aws-cn"),
        ("us-iso-east-1", "aws-iso"),
        ("us-isob-east-1", "aws-iso-b"),  # must not be matched by the us-iso- prefix
        ("eu-isoe-west-1", "aws-iso-e"),
        ("us-isof-south-1", "aws-iso-f"),
        ("us-east-1", "aws"),
        ("some-unknown-region", "aws"),
        ("", "aws"),
    ],
)
def test_partition_from_region_name_fallback(region_name, expected_partition):
    """The region-prefix fallback maps each partition's regions correctly."""
    from enable_bucket_event_notifications import _partition_from_region_name

    assert _partition_from_region_name(region_name) == expected_partition


@pytest.mark.parametrize(
    "region_name, expected_partition",
    [
        ("us-gov-west-1", "aws-us-gov"),
        ("cn-north-1", "aws-cn"),
        ("us-iso-east-1", "aws-iso"),
        ("us-isob-east-1", "aws-iso-b"),
    ],
)
def test_partition_from_region_falls_back_on_unknown_region(
    monkeypatch, region_name, expected_partition
):
    """When botocore doesn't recognize the region, the prefix fallback is used."""
    from botocore.exceptions import UnknownRegionError
    from enable_bucket_event_notifications import partition_from_region

    class FakeSession:
        def __init__(self, region: str):
            self.region_name = region

        def get_partition_for_region(self, _region):
            raise UnknownRegionError(region_name=_region, error_msg="mocked")

    assert partition_from_region(FakeSession(region_name)) == expected_partition


def test_notification_statement_uses_partition_wildcard():
    """The wildcard SourceArn carries the correct partition for non-commercial regions."""
    from enable_bucket_event_notifications import _build_asr_notification_statement

    statement = _build_asr_notification_statement(
        expected_topic_arn="arn:aws-us-gov:sns:us-gov-west-1:123456789012:testTopic",
        account_id="123456789012",
        partition="aws-us-gov",
    )

    assert statement["Condition"]["ArnLike"]["aws:SourceArn"] == "arn:aws-us-gov:s3:::*"
    assert statement["Condition"]["StringEquals"]["aws:SourceAccount"] == "123456789012"
