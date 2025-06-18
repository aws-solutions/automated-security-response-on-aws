# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from layer.utils import get_account_alias, partition_from_region, resource_from_arn
from moto import mock_aws

MOTO_ACCOUNT_ID = "123456789012"


def test_resource_from_arn():
    testarn1 = "arn:aws-us-gov:iam:us-gov-west-1:222222222222:root"
    assert resource_from_arn(testarn1) == "root"
    testarn2 = "arn:aws-cn:s3:::doc-example-bucket"
    assert resource_from_arn(testarn2) == "doc-example-bucket"
    testarn3 = "This is a non-arn string"
    assert resource_from_arn(testarn3) == "This is a non-arn string"


def test_partition_from_region():
    assert partition_from_region("us-gov-west-1") == "aws-us-gov"
    assert partition_from_region("cn-north-1") == "aws-cn"
    # Note: does not validate region name. default expected
    assert partition_from_region("foo") == "aws"
    assert partition_from_region("eu-west-1") == "aws"


@mock_aws
def test_get_account_alias():
    client = boto3.client("organizations", region_name="us-east-1")
    client.create_organization(FeatureSet="ALL")

    account_alias = get_account_alias(MOTO_ACCOUNT_ID)

    assert account_alias == "master"


@mock_aws
def test_get_account_alias_error():
    account_alias = get_account_alias(MOTO_ACCOUNT_ID)

    assert account_alias == "Unknown"
