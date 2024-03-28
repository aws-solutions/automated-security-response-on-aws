# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
import botocore.session
import SetSSLBucketPolicy as remediation
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)


def existing_policy():
    return {
        "Version": "2008-10-17",
        "Id": "ExistingBucketPolicy",
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
            }
        ],
    }


def policy_to_add():
    return {
        "Sid": "AllowSSLRequestsOnly",
        "Action": "s3:*",
        "Effect": "Deny",
        "Resource": ["arn:aws:s3:::abucket", "arn:aws:s3:::abucket/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        "Principal": "*",
    }


def new_policy_json():
    return {
        "Id": "BucketPolicy",
        "Version": "2012-10-17",
        "Statement": [policy_to_add()],
    }


def response_metadata():
    return {
        "ResponseMetadata": {
            "RequestId": "A6NCY16443JH271V",
            "HostId": "vmM0qqMatvgqF2uRvfI79NWUbKaEZHHk49er2WIptAvH420Euq3Ac+cg+CXUEl9kFe3x49Cl/+I=",
            "HTTPStatusCode": 204,
            "HTTPHeaders": {
                "x-amz-id-2": "vmM0qqMatvgqF2uRvfI79NWUbKaEZHHk49er2WIptAvH420Euq3Ac+cg+CXUEl9kFe3x49Cl/+I=",
                "x-amz-request-id": "A6NCY16443JH271V",
                "date": "Wed, 20 Oct 2021 17:40:32 GMT",
                "server": "AmazonS3",
            },
            "RetryAttempts": 0,
        }
    }


def event():
    return {"bucket": "abucket", "accountid": "111111111111", "partition": "aws"}


def test_new_policy(mocker):
    s3_client = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_client_error(
        "get_bucket_policy",
        service_error_code="NoSuchBucketPolicy",
        expected_params={"Bucket": "abucket", "ExpectedBucketOwner": "111111111111"},
    )
    s3_stubber.add_response(
        "put_bucket_policy",
        response_metadata(),
        expected_params={
            "Bucket": "abucket",
            "Policy": json.dumps(new_policy_json(), indent=4),
            "ExpectedBucketOwner": "111111111111",
        },
    )
    s3_stubber.activate()
    mocker.patch("SetSSLBucketPolicy.connect_to_s3", return_value=s3_client)
    assert remediation.add_ssl_bucket_policy(event(), {}) is None
    s3_stubber.deactivate()


def test_add_to_policy(mocker):
    s3_client = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)
    s3_stubber = Stubber(s3_client)
    s3_stubber.add_response(
        "get_bucket_policy",
        {"Policy": json.dumps(existing_policy())},
        expected_params={"Bucket": "abucket", "ExpectedBucketOwner": "111111111111"},
    )
    new_policy = existing_policy()
    new_policy["Statement"].append(policy_to_add())
    print(new_policy)
    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        expected_params={
            "Bucket": "abucket",
            "Policy": json.dumps(new_policy, indent=4),
            "ExpectedBucketOwner": "111111111111",
        },
    )
    s3_stubber.activate()
    mocker.patch("SetSSLBucketPolicy.connect_to_s3", return_value=s3_client)
    assert remediation.add_ssl_bucket_policy(event(), {}) is None
    s3_stubber.deactivate()
