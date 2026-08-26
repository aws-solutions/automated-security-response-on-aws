# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import os

import pytest

# The module filename contains a dot, so standard import won't work.
# Use importlib.util to load it from the file path directly.
_script_dir = os.path.join(os.path.dirname(__file__), "..")
_spec = importlib.util.spec_from_file_location(
    "parse_module",
    os.path.join(_script_dir, "SC_IAMAccessAnalyzer.ExternalAccess_parse.py"),
)
assert _spec is not None and _spec.loader is not None
_parse_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_parse_module)
parse_event = _parse_module.parse_event

ACCOUNT_ID = "123456789012"

S3_FINDING = {
    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/abc-123",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/access-analyzer",
    "AwsAccountId": ACCOUNT_ID,
    "Resources": [
        {
            "Type": "AwsS3Bucket",
            "Id": "arn:aws:s3:::my-test-bucket",
            "Region": "us-east-1",
        }
    ],
}

KMS_FINDING = {
    "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/def-456",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/access-analyzer",
    "AwsAccountId": ACCOUNT_ID,
    "Resources": [
        {
            "Type": "AwsKmsKey",
            "Id": "arn:aws:kms:us-west-2:123456789012:key/12345678-abcd-1234-abcd-123456789012",
            "Region": "us-west-2",
        }
    ],
}


def test_parse_s3_finding():
    result = parse_event({"Finding": S3_FINDING}, None)
    assert result["finding_id"] == S3_FINDING["Id"]
    assert result["product_arn"] == S3_FINDING["ProductArn"]
    assert result["account_id"] == ACCOUNT_ID
    assert result["resource_arn"] == "arn:aws:s3:::my-test-bucket"
    assert result["resource_type"] == "s3"
    assert result["resource_region"] == "us-east-1"
    assert result["object"]["Type"] == "AwsS3Bucket"


def test_parse_kms_finding():
    result = parse_event({"Finding": KMS_FINDING}, None)
    assert result["finding_id"] == KMS_FINDING["Id"]
    expected_arn: str = KMS_FINDING["Resources"][0]["Id"]  # type: ignore[index]
    assert result["resource_arn"] == expected_arn
    assert result["resource_type"] == "kms"
    assert result["resource_region"] == "us-west-2"
    assert result["object"]["Type"] == "AwsKmsKey"


def test_parse_missing_resources():
    finding = {**S3_FINDING, "Resources": []}
    with pytest.raises(ValueError, match="No resources found"):
        parse_event({"Finding": finding}, None)


def test_parse_unsupported_resource_type():
    finding = {
        **S3_FINDING,
        "Resources": [
            {
                "Type": "AwsLambdaFunction",
                "Id": "arn:aws:lambda:us-east-1:123:function:test",
            }
        ],
    }
    with pytest.raises(ValueError, match="Unsupported resource type"):
        parse_event({"Finding": finding}, None)


def test_parse_invalid_account_id():
    finding = {**S3_FINDING, "AwsAccountId": "invalid"}
    with pytest.raises(ValueError, match="Invalid AwsAccountId"):
        parse_event({"Finding": finding}, None)


def test_parse_prefers_resource_owner_account():
    # ARRANGE: org-analyzer finding where AwsAccountId (admin) differs from the resource owner
    finding = {
        **S3_FINDING,
        "AwsAccountId": "111111111111",
        "ProductFields": {"ResourceOwnerAccount": "222222222222"},
    }

    # ACT
    result = parse_event({"Finding": finding}, None)

    # ASSERT: remediation targets the resource owner, not the administrator account
    assert result["account_id"] == "222222222222"


def test_parse_invalid_resource_owner_account():
    # ARRANGE: ResourceOwnerAccount present but malformed
    finding = {
        **S3_FINDING,
        "ProductFields": {"ResourceOwnerAccount": "bad"},
    }

    # ACT / ASSERT
    with pytest.raises(ValueError, match="Invalid ResourceOwnerAccount"):
        parse_event({"Finding": finding}, None)


def test_parse_region_from_arn_fallback():
    """When Region is missing, extract it from the resource ARN."""
    finding = {
        **KMS_FINDING,
        "Resources": [
            {
                "Type": "AwsKmsKey",
                "Id": "arn:aws:kms:eu-west-1:123456789012:key/abcd",
                "Region": "",
            }
        ],
    }
    result = parse_event({"Finding": finding}, None)
    assert result["resource_region"] == "eu-west-1"


def test_parse_s3_region_fallback_empty():
    """S3 ARNs don't contain a region, so fallback should return empty string."""
    finding = {
        **S3_FINDING,
        "Resources": [
            {
                "Type": "AwsS3Bucket",
                "Id": "arn:aws:s3:::my-bucket",
                "Region": "",
            }
        ],
    }
    result = parse_event({"Finding": finding}, None)
    assert result["resource_region"] == ""


def test_parse_invalid_resource_arn():
    """resource_id must be a valid ARN."""
    finding = {
        **S3_FINDING,
        "Resources": [
            {
                "Type": "AwsS3Bucket",
                "Id": "not-an-arn",
                "Region": "us-east-1",
            }
        ],
    }
    with pytest.raises(ValueError, match="Invalid resource ARN"):
        parse_event({"Finding": finding}, None)
