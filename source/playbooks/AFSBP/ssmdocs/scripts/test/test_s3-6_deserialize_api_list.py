# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import deserializeApiList as script


def event():
    return {
        "SerializedList": '{"blacklistedActionPattern":"s3:DeleteBucketPolicy,s3:PutBucketAcl,s3:PutBucketPolicy,s3:PutObjectAcl,s3:PutEncryptionConfiguration"}'
    }


def expected():
    return "s3:DeleteBucketPolicy,s3:PutBucketAcl,s3:PutBucketPolicy,s3:PutObjectAcl,s3:PutEncryptionConfiguration"


def test_extract_list():
    assert script.runbook_handler(event(), {}) == expected()
