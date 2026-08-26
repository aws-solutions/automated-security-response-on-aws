# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# NOTE: moto does not implement securityhub:BatchUpdateFindings.
# patch.object mocks Security Hub at the module boundary. S3 operations are
# mocked via moto. Tests exercise the non-raising core (_execute_remediation);
# parse_event wraps it, assumes the per-control role, and raises on FAILED
# (see TestParseEventRaises).
import importlib.util
import os
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

_script_dir = os.path.join(os.path.dirname(__file__), "..")
_spec = importlib.util.spec_from_file_location(
    "macie_module",
    os.path.join(_script_dir, "SC_Macie.SensitiveDataS3Object.py"),
)
assert (
    _spec is not None and _spec.loader is not None
), "Failed to load SC_Macie.SensitiveDataS3Object module spec"
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

_bucket_name_from_arn = _mod._bucket_name_from_arn
_resolve_ocsf_bucket_name = _mod._resolve_ocsf_bucket_name
_resolve_ocsf_account_id = _mod._resolve_ocsf_account_id
_validate_finding = _mod._validate_finding
_validate_asff_finding = _mod._validate_asff_finding
parse_event = _mod.parse_event

ACCOUNT_ID = "123456789012"
BUCKET_NAME = "my-sensitive-data-bucket"
# Sourced from the environment (not a hardcoded literal) so the test region
# follows the surrounding moto/CI configuration; falls back to us-east-1.
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture(autouse=True)
def _reset_module_session():
    """Reset the module-level session/client cache between tests so a session
    assumed by one test does not leak into the next."""
    _mod._SESSION = None  # type: ignore[attr-defined]
    _mod._reset_clients()
    yield
    _mod._SESSION = None  # type: ignore[attr-defined]
    _mod._reset_clients()


def _execute(event):
    """Call the non-raising core directly (bypasses role assumption)."""
    return _mod._execute_remediation(event, None)


# Real Security Hub V2 OCSF Data Security finding (class_uid 2006) for Macie,
# modeled on a live-captured payload: account at cloud.account.uid, the S3
# object as resources[0] (uid is the bare object key), the bucket as a separate
# AWS::S3::Bucket resource (uid is the bare bucket name, uid_alt is the ARN).
OCSF_FINDING = {
    "class_uid": 2006,
    "finding_info": {
        "uid": "f18414f545f90ac35e01655851a29903",
        "types": ["SensitiveData:S3Object/Personal", "Sensitive Data"],
    },
    "metadata": {
        "product": {
            "uid": "arn:aws:securityhub:us-east-1::productv2/aws/macie",
            "name": "Macie",
        },
    },
    "cloud": {"account": {"uid": ACCOUNT_ID}, "region": REGION},
    "resources": [
        {
            "type": "AWS::S3::Object",
            "uid": "test-data.txt",
            "region": REGION,
            "cloud_partition": "aws",
            "owner": {"account": {"uid": ACCOUNT_ID}},
        },
        {
            "type": "AWS::S3::Bucket",
            "uid": BUCKET_NAME,
            "uid_alt": f"arn:aws:s3:::{BUCKET_NAME}",
            "region": REGION,
            "cloud_partition": "aws",
            "owner": {"account": {"uid": ACCOUNT_ID}},
        },
    ],
}

# ASFF representation (findings/action API replay of the persisted finding).
ASFF_FINDING = {
    "Id": "arn:aws:securityhub:us-east-1:123456789012:product/aws/macie/finding/abc123",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/macie",
    "AwsAccountId": ACCOUNT_ID,
    "Region": REGION,
    "Resources": [
        {
            "Type": "AwsS3Object",
            "Id": f"arn:aws:s3:::{BUCKET_NAME}/sensitive-file.csv",
            "Region": REGION,
        }
    ],
}


class TestBucketNameFromArn:
    def test_object_arn(self):
        assert _bucket_name_from_arn(f"arn:aws:s3:::{BUCKET_NAME}/k.csv") == BUCKET_NAME

    def test_bucket_arn(self):
        assert _bucket_name_from_arn(f"arn:aws:s3:::{BUCKET_NAME}") == BUCKET_NAME

    def test_govcloud(self):
        assert _bucket_name_from_arn("arn:aws-us-gov:s3:::gov-bucket/f") == "gov-bucket"

    def test_non_arn_returns_empty(self):
        assert _bucket_name_from_arn("test-data.txt") == ""

    def test_non_s3_arn_returns_empty(self):
        assert _bucket_name_from_arn("arn:aws:ec2:us-east-1:1:instance/i-a") == ""


class TestResolveOcsfBucketName:
    def test_bucket_resource_bare_name(self):
        assert (
            _resolve_ocsf_bucket_name(resources=OCSF_FINDING["resources"])
            == BUCKET_NAME
        )

    def test_bucket_resource_arn_uid(self):
        resources = [
            {"type": "AWS::S3::Object", "uid": "key.csv"},
            {"type": "AWS::S3::Bucket", "uid": f"arn:aws:s3:::{BUCKET_NAME}"},
        ]
        assert _resolve_ocsf_bucket_name(resources=resources) == BUCKET_NAME

    def test_fallback_to_s3_arn_when_no_bucket_resource(self):
        resources = [
            {"type": "AWS::S3::Object", "uid": f"arn:aws:s3:::{BUCKET_NAME}/k"}
        ]
        assert _resolve_ocsf_bucket_name(resources=resources) == BUCKET_NAME

    def test_raises_when_unresolvable(self):
        resources = [{"type": "AWS::S3::Object", "uid": "test-data.txt"}]
        with pytest.raises(ValueError, match="Could not resolve S3 bucket name"):
            _resolve_ocsf_bucket_name(resources=resources)


class TestResolveOcsfAccountId:
    def test_cloud_account_uid(self):
        assert (
            _resolve_ocsf_account_id(
                finding={"cloud": {"account": {"uid": ACCOUNT_ID}}},
                resource={},
            )
            == ACCOUNT_ID
        )

    def test_owner_account_fallback(self):
        assert (
            _resolve_ocsf_account_id(
                finding={},
                resource={"owner": {"account": {"uid": ACCOUNT_ID}}},
            )
            == ACCOUNT_ID
        )

    def test_resource_account_fallback(self):
        assert (
            _resolve_ocsf_account_id(
                finding={}, resource={"account": {"uid": ACCOUNT_ID}}
            )
            == ACCOUNT_ID
        )


class TestValidateFinding:
    def test_valid_real_ocsf(self):
        validated = _validate_finding(finding=OCSF_FINDING)
        assert validated.account_id == ACCOUNT_ID
        assert validated.resource_region == REGION
        assert validated.bucket_name == BUCKET_NAME
        assert validated.partition == "aws"

    def test_no_resources(self):
        with pytest.raises(ValueError, match="No resources found"):
            _validate_finding(finding={**OCSF_FINDING, "resources": []})

    def test_invalid_account_id(self):
        # cloud.account.uid is the first source _resolve_ocsf_account_id reads;
        # a non-empty bad value short-circuits the fallbacks.
        finding = {
            **OCSF_FINDING,
            "cloud": {"account": {"uid": "bad"}, "region": REGION},
        }
        with pytest.raises(ValueError, match="Invalid account ID"):
            _validate_finding(finding=finding)

    def test_missing_finding_id(self):
        with pytest.raises(ValueError, match="Missing finding_info.uid"):
            _validate_finding(finding={**OCSF_FINDING, "finding_info": {}})

    def test_missing_product_arn(self):
        with pytest.raises(ValueError, match="Missing metadata.product.uid"):
            _validate_finding(finding={**OCSF_FINDING, "metadata": {}})


class TestValidateAsffFinding:
    def test_valid_asff(self):
        validated = _validate_asff_finding(finding=ASFF_FINDING)
        assert validated.account_id == ACCOUNT_ID
        assert validated.resource_region == REGION
        assert validated.bucket_name == BUCKET_NAME
        assert validated.finding_id == ASFF_FINDING["Id"]
        assert validated.product_arn == ASFF_FINDING["ProductArn"]

    def test_reconstructed_asff_bare_bucket_resource(self):
        # A Macie finding replayed through the findings/action API preserves the
        # OCSF-origin values: the object Id is a bare key and the bucket Id is a
        # bare name (no arn:aws:s3::: prefix). The bucket resource must still resolve.
        finding = {
            **ASFF_FINDING,
            "Resources": [
                {"Type": "AWS::S3::Object", "Id": "test-data.txt", "Region": REGION},
                {"Type": "AWS::S3::Bucket", "Id": BUCKET_NAME, "Region": REGION},
            ],
        }
        validated = _validate_asff_finding(finding=finding)
        assert validated.bucket_name == BUCKET_NAME

    def test_invalid_account_id(self):
        with pytest.raises(ValueError, match="Invalid account ID"):
            _validate_asff_finding(finding={**ASFF_FINDING, "AwsAccountId": "bad"})

    def test_no_bucket_arn(self):
        finding = {
            **ASFF_FINDING,
            "Resources": [{"Type": "AwsS3Object", "Id": "not-an-arn"}],
        }
        with pytest.raises(ValueError, match="Could not resolve S3 bucket name"):
            _validate_asff_finding(finding=finding)


class TestExecuteRemediationSuccess:
    @mock_aws
    @patch.object(_mod, "_update_security_hub_finding")
    def test_ocsf_enables_block_public_access(self, mock_update):
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET_NAME)

        result = _execute({"Finding": OCSF_FINDING, "SSMDocName": "test"})

        assert result["status"] == "SUCCESS"
        assert result["bucket_name"] == BUCKET_NAME
        assert result["account_id"] == ACCOUNT_ID
        config = s3.get_public_access_block(
            Bucket=BUCKET_NAME, ExpectedBucketOwner=ACCOUNT_ID
        )["PublicAccessBlockConfiguration"]
        assert config["BlockPublicAcls"] is True
        assert config["IgnorePublicAcls"] is True
        assert config["BlockPublicPolicy"] is True
        assert config["RestrictPublicBuckets"] is True

        update_kwargs = mock_update.call_args[1]
        assert update_kwargs["workflow_status"] == "NOTIFIED"
        assert BUCKET_NAME in update_kwargs["note_text"]
        assert "manual investigation" in update_kwargs["note_text"].lower()

    @mock_aws
    @patch.object(_mod, "_update_security_hub_finding")
    def test_asff_enables_block_public_access(self, mock_update):
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET_NAME)

        result = _execute({"Finding": ASFF_FINDING, "SSMDocName": "test"})

        assert result["status"] == "SUCCESS"
        assert result["bucket_name"] == BUCKET_NAME
        config = s3.get_public_access_block(
            Bucket=BUCKET_NAME, ExpectedBucketOwner=ACCOUNT_ID
        )["PublicAccessBlockConfiguration"]
        assert config["RestrictPublicBuckets"] is True

    @mock_aws
    @patch.object(_mod, "_update_security_hub_finding")
    def test_affected_object(self, mock_update):
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET_NAME)
        result = _execute({"Finding": OCSF_FINDING, "SSMDocName": "test"})
        assert result["object"]["Type"] == "AwsS3Bucket"
        assert result["object"]["Id"] == BUCKET_NAME

    @mock_aws
    @patch.object(_mod, "_update_security_hub_finding")
    def test_security_hub_failure_still_succeeds_with_warning(self, mock_update):
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket=BUCKET_NAME)
        mock_update.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailableException", "Message": "x"}},
            "BatchUpdateFindings",
        )
        result = _execute({"Finding": OCSF_FINDING, "SSMDocName": "test"})
        assert result["status"] == "SUCCESS"
        assert "WARNING" in str(result["message"])


class TestExecuteRemediationFailure:
    @mock_aws
    @patch.object(_mod, "_update_security_hub_finding")
    def test_s3_api_failure_returns_failed_and_notifies(self, mock_update):
        # Do NOT create the bucket — moto raises a real NoSuchBucket error.
        result = _execute({"Finding": OCSF_FINDING, "SSMDocName": "test"})
        assert result["status"] == "FAILED"
        assert "Failed to enable S3 Block Public Access" in str(result["message"])
        assert mock_update.call_args[1]["workflow_status"] == "NOTIFIED"

    def test_unrecognized_shape_returns_failed(self):
        result = _execute({"Finding": {"foo": "bar"}, "SSMDocName": "test"})
        assert result["status"] == "FAILED"
        assert "Invalid finding" in str(result["message"])


class TestParseEventRaises:
    @patch.object(_mod, "_init_remediation_session")
    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_enable_public_access_block")
    def test_success_returns_payload(self, mock_s3, mock_update, mock_session):
        result = parse_event(
            {
                "Finding": OCSF_FINDING,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-Macie.SensitiveDataS3Object-test",
            },
            None,
        )
        assert result["status"] == "SUCCESS"
        mock_session.assert_called_once()

    @patch.object(_mod, "_init_remediation_session")
    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_enable_public_access_block")
    def test_raises_on_failed(self, mock_s3, mock_update, mock_session):
        mock_s3.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "PutPublicAccessBlock"
        )
        with pytest.raises(RuntimeError):
            parse_event(
                {
                    "Finding": OCSF_FINDING,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-Macie.SensitiveDataS3Object-test",
                },
                None,
            )

    def test_missing_role_name_raises(self):
        with pytest.raises(
            ValueError, match="RemediationRoleName parameter is required"
        ):
            parse_event({"Finding": OCSF_FINDING, "SSMDocName": "test"}, None)

    def test_invalid_role_name_raises(self):
        with pytest.raises(ValueError, match="is not a valid IAM role name"):
            parse_event(
                {
                    "Finding": OCSF_FINDING,
                    "SSMDocName": "test",
                    "RemediationRoleName": "bad/role name",
                },
                None,
            )


class TestInitRemediationSession:
    def test_assume_role_failure_raises_session_error(self):
        sts = MagicMock()
        sts.get_caller_identity.return_value = {
            "Account": ACCOUNT_ID,
            "Arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/x/y",
        }
        sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole"
        )
        with patch.object(_mod.boto3, "client", return_value=sts):
            with pytest.raises(_mod.RemediationSessionError):
                _mod._init_remediation_session(role_name="SO0111-Macie-test")
