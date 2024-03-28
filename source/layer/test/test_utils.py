# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from layer.utils import partition_from_region, resource_from_arn


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
