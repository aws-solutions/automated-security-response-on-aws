# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from unittest.mock import Mock, patch

import EnableCloudTrailToCloudWatchLogging_fixbucketpolicy as fix_policy
from botocore.exceptions import ClientError

TRAIL_NAME = "test-trail"
TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail"
BUCKET_NAME = "test-cloudtrail-bucket"
ACCOUNT = "123456789012"
PARTITION = "aws"


def _event():
    return {"trail_name": TRAIL_NAME, "partition": PARTITION, "account": ACCOUNT}


def test_create_cloudtrail_bucket_policy_builds_expected_statements():
    policy = fix_policy.create_cloudtrail_bucket_policy(
        BUCKET_NAME, TRAIL_ARN, PARTITION, ACCOUNT
    )
    sids = {stmt["Sid"] for stmt in policy["Statement"]}
    assert sids == {
        "AWSCloudTrailAclCheck20150319",
        "AWSCloudTrailWrite20150319",
        "AllowSSLRequestsOnly",
    }
    write_stmt = next(
        s for s in policy["Statement"] if s["Sid"] == "AWSCloudTrailWrite20150319"
    )
    assert (
        write_stmt["Resource"]
        == f"arn:{PARTITION}:s3:::{BUCKET_NAME}/AWSLogs/{ACCOUNT}/*"
    )


def test_merge_bucket_policies_returns_new_when_existing_empty():
    new = {"Statement": [{"Sid": "A"}]}
    assert fix_policy.merge_bucket_policies(None, new) == new
    assert fix_policy.merge_bucket_policies({}, new) == new
    assert fix_policy.merge_bucket_policies({"Version": "2012-10-17"}, new) == new


def test_merge_bucket_policies_appends_new_sid():
    existing = {"Statement": [{"Sid": "Existing"}]}
    new = {"Statement": [{"Sid": "New"}]}
    merged = fix_policy.merge_bucket_policies(existing, new)
    sids = {stmt["Sid"] for stmt in merged["Statement"]}
    assert sids == {"Existing", "New"}


def test_merge_bucket_policies_replaces_matching_sid():
    existing = {"Statement": [{"Sid": "Dup", "Effect": "Allow"}]}
    new = {"Statement": [{"Sid": "Dup", "Effect": "Deny"}]}
    merged = fix_policy.merge_bucket_policies(existing, new)
    assert len(merged["Statement"]) == 1
    assert merged["Statement"][0]["Effect"] == "Deny"


@patch("EnableCloudTrailToCloudWatchLogging_fixbucketpolicy.boto3.client")
def test_fix_bucket_policy_no_existing_policy(mock_boto_client):
    mock_s3 = Mock()
    mock_cloudtrail = Mock()
    mock_boto_client.side_effect = [mock_s3, mock_cloudtrail]

    mock_cloudtrail.get_trail.return_value = {
        "Trail": {"S3BucketName": BUCKET_NAME, "TrailARN": TRAIL_ARN}
    }
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )

    result = fix_policy.fix_cloudtrail_bucket_policy_for_logging(_event(), None)

    assert result["output"]["PolicyMerged"] is False
    assert result["output"]["BucketName"] == BUCKET_NAME
    # ExpectedBucketOwner must be asserted on both read and write.
    mock_s3.get_bucket_policy.assert_called_once_with(
        Bucket=BUCKET_NAME, ExpectedBucketOwner=ACCOUNT
    )
    _, put_kwargs = mock_s3.put_bucket_policy.call_args
    assert put_kwargs["ExpectedBucketOwner"] == ACCOUNT


@patch("EnableCloudTrailToCloudWatchLogging_fixbucketpolicy.boto3.client")
def test_fix_bucket_policy_merges_existing_policy(mock_boto_client):
    mock_s3 = Mock()
    mock_cloudtrail = Mock()
    mock_boto_client.side_effect = [mock_s3, mock_cloudtrail]

    mock_cloudtrail.get_trail.return_value = {
        "Trail": {"S3BucketName": BUCKET_NAME, "TrailARN": TRAIL_ARN}
    }
    existing_policy = {"Statement": [{"Sid": "CustomExisting", "Effect": "Allow"}]}
    mock_s3.get_bucket_policy.return_value = {"Policy": json.dumps(existing_policy)}

    result = fix_policy.fix_cloudtrail_bucket_policy_for_logging(_event(), None)

    assert result["output"]["PolicyMerged"] is True
    _, put_kwargs = mock_s3.put_bucket_policy.call_args
    written = json.loads(put_kwargs["Policy"])
    sids = {stmt["Sid"] for stmt in written["Statement"]}
    assert "CustomExisting" in sids
    assert "AWSCloudTrailAclCheck20150319" in sids


@patch("EnableCloudTrailToCloudWatchLogging_fixbucketpolicy.boto3.client")
def test_fix_bucket_policy_missing_bucket_returns_error(mock_boto_client):
    mock_s3 = Mock()
    mock_cloudtrail = Mock()
    mock_boto_client.side_effect = [mock_s3, mock_cloudtrail]

    mock_cloudtrail.get_trail.return_value = {
        "Trail": {"S3BucketName": "", "TrailARN": ""}
    }

    result = fix_policy.fix_cloudtrail_bucket_policy_for_logging(_event(), None)

    assert "Error" in result["output"]
    assert result["output"]["TrailName"] == TRAIL_NAME
    mock_s3.put_bucket_policy.assert_not_called()


@patch(
    "EnableCloudTrailToCloudWatchLogging_fixbucketpolicy.time.sleep", return_value=None
)
@patch("EnableCloudTrailToCloudWatchLogging_fixbucketpolicy.boto3.client")
def test_fix_bucket_policy_retries_on_slowdown(mock_boto_client, _mock_sleep):
    mock_s3 = Mock()
    mock_cloudtrail = Mock()
    mock_boto_client.side_effect = [mock_s3, mock_cloudtrail]

    mock_cloudtrail.get_trail.return_value = {
        "Trail": {"S3BucketName": BUCKET_NAME, "TrailARN": TRAIL_ARN}
    }
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.put_bucket_policy.side_effect = [
        ClientError({"Error": {"Code": "SlowDown"}}, "PutBucketPolicy"),
        {},
    ]

    result = fix_policy.fix_cloudtrail_bucket_policy_for_logging(_event(), None)

    assert result["output"]["BucketName"] == BUCKET_NAME
    assert mock_s3.put_bucket_policy.call_count == 2


@patch("EnableCloudTrailToCloudWatchLogging_fixbucketpolicy.boto3.client")
def test_fix_bucket_policy_get_policy_non_recoverable_error(mock_boto_client):
    mock_s3 = Mock()
    mock_cloudtrail = Mock()
    mock_boto_client.side_effect = [mock_s3, mock_cloudtrail]

    mock_cloudtrail.get_trail.return_value = {
        "Trail": {"S3BucketName": BUCKET_NAME, "TrailARN": TRAIL_ARN}
    }
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "GetBucketPolicy"
    )

    result = fix_policy.fix_cloudtrail_bucket_policy_for_logging(_event(), None)

    assert "Error" in result["output"]
    mock_s3.put_bucket_policy.assert_not_called()


@patch("EnableCloudTrailToCloudWatchLogging_fixbucketpolicy.boto3.client")
def test_fix_bucket_policy_put_non_retryable_error(mock_boto_client):
    mock_s3 = Mock()
    mock_cloudtrail = Mock()
    mock_boto_client.side_effect = [mock_s3, mock_cloudtrail]

    mock_cloudtrail.get_trail.return_value = {
        "Trail": {"S3BucketName": BUCKET_NAME, "TrailARN": TRAIL_ARN}
    }
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.put_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "PutBucketPolicy"
    )

    result = fix_policy.fix_cloudtrail_bucket_policy_for_logging(_event(), None)

    assert "Error" in result["output"]
    assert mock_s3.put_bucket_policy.call_count == 1
