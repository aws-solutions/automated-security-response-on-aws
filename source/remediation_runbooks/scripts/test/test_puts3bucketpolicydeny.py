# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
import botocore.session
import PutS3BucketPolicyDeny as remediation
import pytest
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)


@pytest.fixture(autouse=True)
def mock_get_partition(mocker):
    mocker.patch("PutS3BucketPolicyDeny.get_partition", return_value="aws")


def policy_basic_existing():
    return {
        "Version": "2008-10-17",
        "Id": "MyBucketPolicy",
        "Statement": [
            {
                "Sid": "S3ReplicationPolicyStmt1",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                "Action": [
                    "s3:GetBucketVersioning",
                    "s3:PutBucketVersioning",
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete",
                ],
                "Resource": ["arn:aws:s3:::abucket", "arn:aws:s3:::abucket/*"],
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
            },
        ],
    }


def policy_basic_expected():
    return {
        "Version": "2008-10-17",
        "Id": "MyBucketPolicy",
        "Statement": [
            {
                "Sid": "S3ReplicationPolicyStmt1",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                "Action": [
                    "s3:GetBucketVersioning",
                    "s3:PutBucketVersioning",
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete",
                ],
                "Resource": ["arn:aws:s3:::abucket", "arn:aws:s3:::abucket/*"],
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
            },
            {
                "Effect": "Deny",
                "Principal": {
                    "AWS": ["arn:aws:iam::111122223333:root"],
                },
                "Action": [
                    "s3:DeleteBucketPolicy",
                    "s3:PutBucketAcl",
                    "s3:PutBucketPolicy",
                    "s3:PutObjectAcl",
                    "s3:PutEncryptionConfiguration",
                ],
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
            },
        ],
    }


def policy_multi_principal_existing():
    return {
        "Version": "2008-10-17",
        "Id": "MyBucketPolicy",
        "Statement": [
            {
                "Sid": "S3ReplicationPolicyStmt1",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::111122223333:root",
                        "arn:aws:iam::111122223333:user/Dave",
                        "arn:aws:iam::222233334444:user/Lalit",
                    ]
                },
                "Action": [
                    "s3:GetBucketVersioning",
                    "s3:PutBucketVersioning",
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete",
                ],
                "Resource": ["arn:aws:s3:::abucket", "arn:aws:s3:::abucket/*"],
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::111122223333:root",
                    "Service": "ssm.amazonaws.com",
                },
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
            },
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
            },
        ],
    }


def policy_multi_principal_expected():
    return {
        "Version": "2008-10-17",
        "Id": "MyBucketPolicy",
        "Statement": [
            {
                "Sid": "S3ReplicationPolicyStmt1",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::111122223333:root",
                        "arn:aws:iam::111122223333:user/Dave",
                        "arn:aws:iam::222233334444:user/Lalit",
                    ]
                },
                "Action": [
                    "s3:GetBucketVersioning",
                    "s3:PutBucketVersioning",
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete",
                ],
                "Resource": ["arn:aws:s3:::abucket", "arn:aws:s3:::abucket/*"],
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::111122223333:root",
                    "Service": "ssm.amazonaws.com",
                },
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
            },
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
            },
            {
                "Effect": "Deny",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::111122223333:user/Dave",
                        "arn:aws:iam::111122223333:root",
                    ]
                },
                "Action": [
                    "s3:DeleteBucketPolicy",
                    "s3:PutBucketAcl",
                    "s3:PutBucketPolicy",
                    "s3:PutObjectAcl",
                    "s3:PutEncryptionConfiguration",
                ],
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
            },
        ],
    }


def policy_statement_no_aws_principals():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": "arn:aws:s3:::aws-cloudtrail-logs-222233334444-d425bf6a",
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::aws-cloudtrail-logs-222233334444-d425bf6a/AWSLogs/222233334444/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
            {
                "Sid": "ExternalAccount",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:user/test"},
                "Action": "s3:PutObjectAcl",
                "Resource": "arn:aws:s3:::aws-cloudtrail-logs-222233334444-d425bf6a/*",
            },
        ],
    }


def policy_statement_no_aws_principals_expected():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": "arn:aws:s3:::aws-cloudtrail-logs-222233334444-d425bf6a",
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::aws-cloudtrail-logs-222233334444-d425bf6a/AWSLogs/222233334444/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
            {
                "Sid": "ExternalAccount",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:user/test"},
                "Action": "s3:PutObjectAcl",
                "Resource": "arn:aws:s3:::aws-cloudtrail-logs-222233334444-d425bf6a/*",
            },
            {
                "Effect": "Deny",
                "Principal": {"AWS": ["arn:aws:iam::111122223333:user/test"]},
                "Action": [
                    "s3:DeleteBucketPolicy",
                    "s3:PutBucketAcl",
                    "s3:PutBucketPolicy",
                    "s3:PutObjectAcl",
                    "s3:PutEncryptionConfiguration",
                ],
                "Resource": [
                    "arn:aws:s3:::aws-cloudtrail-logs-222233334444-d425bf6a",
                    "arn:aws:s3:::aws-cloudtrail-logs-222233334444-d425bf6a/*",
                ],
            },
        ],
    }


def policy_only_star_principals():
    return {
        "Version": "2008-10-17",
        "Id": "MyBucketPolicy",
        "Statement": [
            {
                "Sid": "S3ReplicationPolicyStmt1",
                "Effect": "Allow",
                "Principal": "*",
                "Action": [
                    "s3:DeleteBucketPolicy",
                    "s3:PutBucketAcl",
                ],
                "Resource": ["arn:aws:s3:::abucket", "arn:aws:s3:::abucket/*"],
            },
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"],
            },
        ],
    }


def event():
    return {
        "bucket": "example",
        "accountid": "222233334444",
        "denylist": "s3:DeleteBucketPolicy,s3:PutBucketAcl,s3:PutBucketPolicy,s3:PutObjectAcl,s3:PutEncryptionConfiguration",
    }


def test_new_policy(mocker):
    s3_client = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(policy_basic_existing())},
        expected_params={"Bucket": "example", "ExpectedBucketOwner": "222233334444"},
    )
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        expected_params={
            "Bucket": "example",
            "ExpectedBucketOwner": "222233334444",
            "Policy": json.dumps(policy_basic_expected()),
        },
    )
    s3_stubber.activate()
    mocker.patch("PutS3BucketPolicyDeny.connect_to_s3", return_value=s3_client)
    assert remediation.update_bucket_policy(event(), {}) is None
    s3_stubber.deactivate()


def test_new_policy_multiple(mocker):
    s3_client = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(policy_multi_principal_existing())},
        expected_params={"Bucket": "example", "ExpectedBucketOwner": "222233334444"},
    )
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        expected_params={
            "Bucket": "example",
            "ExpectedBucketOwner": "222233334444",
            "Policy": json.dumps(policy_multi_principal_expected()),
        },
    )
    s3_stubber.activate()
    mocker.patch("PutS3BucketPolicyDeny.connect_to_s3", return_value=s3_client)
    assert remediation.update_bucket_policy(event(), {}) is None
    s3_stubber.deactivate()


def test_policy_statement_no_aws_principals(mocker):
    s3_client = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)
    s3_stubber = Stubber(s3_client)
    bucket_name = "aws-cloudtrail-logs-222233334444-d425bf6a"
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(policy_statement_no_aws_principals())},
        expected_params={"Bucket": bucket_name, "ExpectedBucketOwner": "222233334444"},
    )
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        expected_params={
            "Bucket": bucket_name,
            "ExpectedBucketOwner": "222233334444",
            "Policy": json.dumps(policy_statement_no_aws_principals_expected()),
        },
    )
    s3_stubber.activate()
    mocker.patch("PutS3BucketPolicyDeny.connect_to_s3", return_value=s3_client)
    this_event = event()
    this_event["bucket"] = bucket_name
    assert remediation.update_bucket_policy(this_event, {}) is None
    s3_stubber.deactivate()


def test_policy_statement_only_star_principal(mocker):
    s3_client = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(policy_only_star_principals())},
        expected_params={"Bucket": "example", "ExpectedBucketOwner": "222233334444"},
    )
    s3_stubber.activate()
    mocker.patch("PutS3BucketPolicyDeny.connect_to_s3", return_value=s3_client)

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        remediation.update_bucket_policy(event(), {})
    bucket_name = event().get("bucket")
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == f"Unable to create an explicit deny statement for {bucket_name}"
    )

    s3_stubber.deactivate()
