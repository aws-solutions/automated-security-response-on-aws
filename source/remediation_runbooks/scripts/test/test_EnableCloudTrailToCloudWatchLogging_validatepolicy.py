# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from unittest.mock import Mock, patch

import EnableCloudTrailToCloudWatchLogging_validatepolicy as validate_policy
from botocore.exceptions import ClientError

TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail"
BUCKET_NAME = "test-cloudtrail-bucket"


def test_validate_policy_statements_valid_policy():
    policy = {
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Condition": {"StringEquals": {"AWS:SourceArn": TRAIL_ARN}},
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Condition": {"StringEquals": {"AWS:SourceArn": TRAIL_ARN}},
            },
            {
                "Sid": "AllowSSLRequestsOnly",
                "Effect": "Deny",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ]
    }

    result = validate_policy.validate_cloudtrail_policy_statements(policy, TRAIL_ARN)

    assert result["valid"] is True
    assert result["missing_statements"] == []
    assert result["issues"] == []


def test_validate_policy_statements_missing_acl_check():
    policy = {
        "Statement": [
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Condition": {"StringEquals": {"AWS:SourceArn": TRAIL_ARN}},
            }
        ]
    }

    result = validate_policy.validate_cloudtrail_policy_statements(policy, TRAIL_ARN)

    assert result["valid"] is False
    assert "CloudTrail ACL check statement" in result["missing_statements"]


def test_validate_policy_statements_empty_policy():
    result = validate_policy.validate_cloudtrail_policy_statements({}, TRAIL_ARN)

    assert result["valid"] is False
    assert "No policy statements found" in result["issues"]


def test_validate_policy_statements_no_statements():
    policy = {"Version": "2012-10-17"}
    result = validate_policy.validate_cloudtrail_policy_statements(policy, TRAIL_ARN)

    assert result["valid"] is False
    assert "No policy statements found" in result["issues"]


@patch("EnableCloudTrailToCloudWatchLogging_validatepolicy.boto3.client")
def test_validate_cloudtrail_bucket_policy_success(mock_boto_client):
    mock_cloudtrail = Mock()
    mock_s3 = Mock()
    mock_boto_client.side_effect = [mock_s3, mock_cloudtrail]

    mock_cloudtrail.get_trail.return_value = {
        "Trail": {"S3BucketName": BUCKET_NAME, "TrailARN": TRAIL_ARN}
    }

    valid_policy = {
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Condition": {"StringEquals": {"AWS:SourceArn": TRAIL_ARN}},
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Condition": {"StringEquals": {"AWS:SourceArn": TRAIL_ARN}},
            },
            {
                "Sid": "AllowSSLRequestsOnly",
                "Effect": "Deny",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ]
    }

    mock_s3.get_bucket_policy.return_value = {"Policy": json.dumps(valid_policy)}

    result = validate_policy.validate_cloudtrail_bucket_policy(
        {"trail_name": "test-trail"}, {}
    )

    assert result["output"]["Valid"] is True
    assert result["output"]["BucketName"] == BUCKET_NAME
    assert result["output"]["TrailArn"] == TRAIL_ARN


@patch("EnableCloudTrailToCloudWatchLogging_validatepolicy.boto3.client")
def test_validate_cloudtrail_bucket_policy_no_policy(mock_boto_client):
    mock_cloudtrail = Mock()
    mock_s3 = Mock()
    mock_boto_client.side_effect = [mock_s3, mock_cloudtrail]

    mock_cloudtrail.get_trail.return_value = {
        "Trail": {"S3BucketName": BUCKET_NAME, "TrailARN": TRAIL_ARN}
    }

    mock_s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )

    result = validate_policy.validate_cloudtrail_bucket_policy(
        {"trail_name": "test-trail"}, {}
    )

    assert result["output"]["Valid"] is False
    assert "No bucket policy found" in result["output"]["Message"]


@patch("EnableCloudTrailToCloudWatchLogging_validatepolicy.boto3.client")
def test_validate_cloudtrail_bucket_policy_invalid_policy(mock_boto_client):
    mock_cloudtrail = Mock()
    mock_s3 = Mock()
    mock_boto_client.side_effect = [mock_s3, mock_cloudtrail]

    mock_cloudtrail.get_trail.return_value = {
        "Trail": {"S3BucketName": BUCKET_NAME, "TrailARN": TRAIL_ARN}
    }

    invalid_policy = {"Statement": [{"Sid": "SomeOtherStatement"}]}
    mock_s3.get_bucket_policy.return_value = {"Policy": json.dumps(invalid_policy)}

    result = validate_policy.validate_cloudtrail_bucket_policy(
        {"trail_name": "test-trail"}, {}
    )

    assert result["output"]["Valid"] is False
    assert "validation failed" in result["output"]["Message"]
    assert len(result["output"]["MissingStatements"]) == 3


def test_get_missing_statements():
    checks_all_pass = {"acl_check": True, "put_object": True, "ssl_only": True}
    assert validate_policy._get_missing_statements(checks_all_pass) == []

    checks_some_fail = {"acl_check": False, "put_object": True, "ssl_only": False}
    missing = validate_policy._get_missing_statements(checks_some_fail)
    assert len(missing) == 2
    assert "CloudTrail ACL check statement" in missing


def test_validate_policy_statement():
    checks = {"acl_check": False, "put_object": False, "ssl_only": False}

    acl_stmt = {
        "Sid": "AWSCloudTrailAclCheck20150319",
        "Effect": "Allow",
        "Principal": {"Service": "cloudtrail.amazonaws.com"},
        "Action": "s3:GetBucketAcl",
        "Condition": {"StringEquals": {"AWS:SourceArn": TRAIL_ARN}},
    }

    validate_policy._validate_policy_statement(acl_stmt, TRAIL_ARN, checks)
    assert checks["acl_check"] is True
