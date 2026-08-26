# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Configure a CloudFormation stack with an SNS topic for notifications, creating the topic if it does
not already exist
"""
import json
from typing import TYPE_CHECKING, Any, List, TypedDict

import boto3
from botocore.config import Config
from botocore.exceptions import UnknownRegionError

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.typing import LambdaContext
    from mypy_boto3_sns.client import SNSClient
else:
    LambdaContext = object
    SNSClient = object

boto_config = Config(retries={"mode": "standard"})

# Sid of the consolidated ASR statement in the SNS topic policy. A single
# statement grants s3.amazonaws.com permission to publish for every bucket in
# the account, scoped by aws:SourceAccount. Because the statement does not list
# individual bucket ARNs, the policy stays a fixed small size no matter how many
# buckets are remediated (see _build_asr_notification_statement).
_ASR_S3_NOTIFICATION_SID = "ASR S3 Notification Policy"
_SOURCE_ARN_CONDITION_KEY = "aws:SourceArn"


def _build_asr_notification_statement(
    *, expected_topic_arn: str, account_id: str, partition: str
) -> dict[str, Any]:
    """Build the consolidated ASR S3->SNS notification policy statement.

    The statement allows any bucket in `account_id` to publish to the topic:
    `aws:SourceArn` matches every bucket ARN in the partition (`arn:<partition>:s3:::*`)
    while `aws:SourceAccount` restricts publishers to the finding's account, so
    buckets in other accounts cannot wire their events to this topic. Using a
    constant condition keeps the policy at a fixed size regardless of how many
    buckets share the topic.
    """
    return {
        "Sid": _ASR_S3_NOTIFICATION_SID,
        "Effect": "Allow",
        "Principal": {"Service": "s3.amazonaws.com"},
        "Action": ["SNS:Publish"],
        "Resource": expected_topic_arn,
        "Condition": {
            "ArnLike": {_SOURCE_ARN_CONDITION_KEY: f"arn:{partition}:s3:::*"},
            "StringEquals": {"aws:SourceAccount": account_id},
        },
    }


class Event(TypedDict):
    bucket_name: str
    topic_name: str
    account_id: str
    event_types: List[str]


class Output(TypedDict):
    NotificationARNs: str
    resource_arn: str


def lambda_handler(event: Event, _: LambdaContext) -> Output:
    """
    Configure a bucket with an SNS topic for notifications,
    creating the topic if it does not already exist

    `event` should have the following keys and values:
    `bucket_name`: the ARN of the CloudFormation stack to be updated
    `topic_name`: the name of the SQS Queue to create and configure for notifications
    `account_id`: account id that contains the bucket that will have event notifications configured
    `event_types`: the list of events that will have notifications alerted on.

    `context` is ignored
    """
    bucket_name = event["bucket_name"]
    topic_name = event["topic_name"]
    account_id = event["account_id"]
    event_types = event["event_types"]
    topic_arn = get_or_create_topic(topic_name, account_id)
    configure_notifications(bucket_name, topic_arn, event_types, account_id)
    result = assert_bucket_notifcations_configured(bucket_name, account_id)
    result["resource_arn"] = topic_arn
    return result


# Region-prefix -> partition mapping, ordered most-specific-first so that
# e.g. "us-isob-" is matched before "us-iso-". Used as a fallback when botocore
# does not recognize the region (its endpoints data can lag behind newly
# launched ISO regions), so the SNS/S3 ARNs we build still carry the correct
# partition instead of defaulting to commercial "aws".
_REGION_PREFIX_TO_PARTITION = (
    ("us-gov-", "aws-us-gov"),
    ("cn-", "aws-cn"),
    ("us-isob-", "aws-iso-b"),
    ("us-iso-", "aws-iso"),
    ("eu-isoe-", "aws-iso-e"),
    ("us-isof-", "aws-iso-f"),
)


def _partition_from_region_name(region_name: str) -> str:
    """Best-effort partition lookup from a region name prefix, defaulting to aws."""
    for prefix, partition in _REGION_PREFIX_TO_PARTITION:
        if region_name and region_name.startswith(prefix):
            return partition
    return "aws"


def partition_from_region(session: boto3.session.Session) -> str:
    """
    returns the partition for a given region
    On success returns the partition reported by botocore
    On failure falls back to a region-prefix lookup (defaulting to aws)
    """
    try:
        partition = session.get_partition_for_region(session.region_name)
    except UnknownRegionError:
        return _partition_from_region_name(session.region_name)

    return partition


def _ensure_asr_statement(
    policy_dict: dict[str, Any],
    *,
    expected_topic_arn: str,
    account_id: str,
    partition: str,
) -> bool:
    """Ensure the consolidated ASR notification statement is present and correct.

    Returns True if the policy was changed (and therefore needs to be persisted),
    False if it already contained the desired statement.
    """
    desired_statement = _build_asr_notification_statement(
        expected_topic_arn=expected_topic_arn,
        account_id=account_id,
        partition=partition,
    )

    for index, statement in enumerate(policy_dict["Statement"]):
        if statement.get("Sid") == _ASR_S3_NOTIFICATION_SID:
            if statement == desired_statement:
                return False
            # Upgrade a legacy per-bucket-ARN statement to the constant wildcard form
            policy_dict["Statement"][index] = desired_statement
            return True

    policy_dict["Statement"].append(desired_statement)
    return True


def get_or_create_topic(topic_name: str, account_id: str) -> str:
    """Get the SNS topic arn used to configure notifications, creating it if it does not already exist.

    The topic policy carries a single consolidated statement that authorizes every bucket in
    `account_id` to publish (scoped by aws:SourceAccount), so the policy size does not grow with
    the number of remediated buckets.
    """
    sns: SNSClient = boto3.client("sns", config=boto_config)
    session = boto3.session.Session()
    region = session.region_name
    partition = partition_from_region(session)
    expected_topic_arn = f"arn:{partition}:sns:{region}:{account_id}:{topic_name}"

    try:
        topic_attributes = sns.get_topic_attributes(TopicArn=expected_topic_arn)
        policy_dict = json.loads(topic_attributes["Attributes"]["Policy"])

        if _ensure_asr_statement(
            policy_dict,
            expected_topic_arn=expected_topic_arn,
            account_id=account_id,
            partition=partition,
        ):
            sns.set_topic_attributes(
                TopicArn=expected_topic_arn,
                AttributeName="Policy",
                AttributeValue=json.dumps(policy_dict),
            )
        return expected_topic_arn
    except Exception as e:
        error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if error_code in ("NotFound", "NotFoundException"):
            pass  # Topic doesn't exist — create below
        else:
            raise

    # Create a fresh topic with the consolidated policy
    policy = {
        "Version": "2012-10-17",
        "Id": "ASR Notification Policy",
        "Statement": [
            _build_asr_notification_statement(
                expected_topic_arn=expected_topic_arn,
                account_id=account_id,
                partition=partition,
            )
        ],
    }
    response = sns.create_topic(
        Name=topic_name,
        Attributes={"Policy": json.dumps(policy)},
    )
    return response["TopicArn"]


def configure_notifications(
    bucket_name: str, topic_arn: str, event_types: List[str], account_id: str
) -> None:
    """Configure the bucket `bucket_name` to notify the sns topic with ARN `topic_arn`"""
    s3 = boto3.client("s3", config=boto_config)
    # ExpectedBucketOwner asserts the bucket is owned by the finding's account so
    # a sniped/re-created bucket in another account cannot have ASR wire its event
    # notifications to our topic (CWE-283).
    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        ExpectedBucketOwner=account_id,
        NotificationConfiguration={
            "TopicConfigurations": [
                {
                    "Id": "ASR Bucket Notification Topic Config",
                    "Events": event_types,
                    "TopicArn": topic_arn,
                }
            ]
        },
    )


def assert_bucket_notifcations_configured(bucket_name: str, account_id: str):
    """
    Verify that the bucket `bucket_name` is configured to update the SNS topic
    with ARN `topic_arn`
    """
    s3 = boto3.client("s3", config=boto_config)
    notification_configuration = s3.get_bucket_notification_configuration(
        Bucket=bucket_name, ExpectedBucketOwner=account_id
    )
    try:
        return {
            "NotificationARNs": notification_configuration["TopicConfigurations"][0][
                "TopicArn"
            ]
        }
    except Exception:
        raise RuntimeError(
            f"ERROR: {bucket_name} was not configured with notifications"
        )
