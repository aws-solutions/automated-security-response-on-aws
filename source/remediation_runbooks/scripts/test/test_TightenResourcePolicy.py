# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from typing import Any

import boto3
import pytest
import TightenResourcePolicy as remediation
from botocore.config import Config
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
BUCKET_NAME = "my-test-bucket"
BUCKET_ARN = f"arn:aws:s3:::{BUCKET_NAME}"
KMS_KEY_ARN = (
    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
)
ACCOUNT_ID = "123456789012"
ORG_ID = "o-exampleorgid"
PARTITION = "aws"


WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowPublic",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
        }
    ],
}

NO_WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowSpecific",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
        }
    ],
}

DENY_WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyNonTLS",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        },
        {
            "Sid": "AllowPublic",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
        },
    ],
}


WILDCARD_PLUS_EXTERNAL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "MixedPrincipals",
            "Effect": "Allow",
            "Principal": {"AWS": ["*", "arn:aws:iam::999999999999:root"]},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
        }
    ],
}


def test_is_wildcard_principal_star():
    assert remediation.is_wildcard_principal("*") is True


def test_is_wildcard_principal_aws_star():
    assert remediation.is_wildcard_principal({"AWS": "*"}) is True


def test_is_wildcard_principal_aws_list_star():
    assert (
        remediation.is_wildcard_principal({"AWS": ["*", "arn:aws:iam::123:root"]})
        is True
    )


def test_is_wildcard_principal_specific():
    assert remediation.is_wildcard_principal({"AWS": "arn:aws:iam::123:root"}) is False


def test_is_wildcard_principal_service():
    assert remediation.is_wildcard_principal({"Service": "s3.amazonaws.com"}) is False


def test_replace_wildcard_principal_star():
    result = remediation.replace_wildcard_principal(
        "*", account_id=ACCOUNT_ID, partition=PARTITION
    )
    assert result == {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}


def test_replace_wildcard_principal_aws_star():
    result = remediation.replace_wildcard_principal(
        {"AWS": "*"}, account_id=ACCOUNT_ID, partition=PARTITION
    )
    assert result == {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}


def test_replace_wildcard_principal_aws_list():
    result = remediation.replace_wildcard_principal(
        {"AWS": ["*", "arn:aws:iam::999:root"]},
        account_id=ACCOUNT_ID,
        partition=PARTITION,
    )
    assert result == {
        "AWS": [f"arn:aws:iam::{ACCOUNT_ID}:root", "arn:aws:iam::999:root"]
    }


def test_replace_wildcard_principal_govcloud():
    result = remediation.replace_wildcard_principal(
        "*", account_id=ACCOUNT_ID, partition="aws-us-gov"
    )
    assert result == {"AWS": f"arn:aws-us-gov:iam::{ACCOUNT_ID}:root"}


def test_replace_wildcard_principal_china():
    result = remediation.replace_wildcard_principal(
        "*", account_id=ACCOUNT_ID, partition="aws-cn"
    )
    assert result == {"AWS": f"arn:aws-cn:iam::{ACCOUNT_ID}:root"}


def test_add_org_condition_new():
    statement = {"Effect": "Allow"}
    remediation.add_org_condition(statement, ORG_ID)
    assert statement["Condition"]["StringEquals"]["aws:PrincipalOrgID"] == ORG_ID


def test_add_org_condition_existing():
    statement = {
        "Effect": "Allow",
        "Condition": {"StringEquals": {"s3:prefix": "test"}},
    }
    remediation.add_org_condition(statement, ORG_ID)
    assert statement["Condition"]["StringEquals"]["aws:PrincipalOrgID"] == ORG_ID
    assert statement["Condition"]["StringEquals"]["s3:prefix"] == "test"


def test_tighten_policy_with_wildcard():
    policy = json.loads(json.dumps(WILDCARD_POLICY))
    count = remediation.tighten_policy(
        policy, account_id=ACCOUNT_ID, organization_id=ORG_ID, partition=PARTITION
    )
    assert count == 1
    stmt = policy["Statement"][0]
    assert stmt["Principal"] == {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}
    assert stmt["Condition"]["StringEquals"]["aws:PrincipalOrgID"] == ORG_ID


def test_tighten_policy_without_wildcard():
    policy = json.loads(json.dumps(NO_WILDCARD_POLICY))
    count = remediation.tighten_policy(
        policy, account_id=ACCOUNT_ID, organization_id=ORG_ID, partition=PARTITION
    )
    assert count == 0


def test_tighten_policy_no_org():
    policy = json.loads(json.dumps(WILDCARD_POLICY))
    count = remediation.tighten_policy(
        policy, account_id=ACCOUNT_ID, organization_id=None, partition=PARTITION
    )
    assert count == 1
    stmt = policy["Statement"][0]
    assert stmt["Principal"] == {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}
    assert "Condition" not in stmt


def test_tighten_policy_skips_deny_statements():
    """Deny statements with wildcard principals should not be modified."""
    policy = json.loads(json.dumps(DENY_WILDCARD_POLICY))
    count = remediation.tighten_policy(
        policy, account_id=ACCOUNT_ID, organization_id=ORG_ID, partition=PARTITION
    )
    # Only the Allow statement should be modified, not the Deny
    assert count == 1
    deny_stmt = policy["Statement"][0]
    assert deny_stmt["Effect"] == "Deny"
    assert deny_stmt["Principal"] == "*"  # Unchanged
    allow_stmt = policy["Statement"][1]
    assert allow_stmt["Effect"] == "Allow"
    assert allow_stmt["Principal"] == {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}


def test_extract_s3_bucket_name():
    assert remediation.extract_s3_bucket_name("arn:aws:s3:::my-bucket") == "my-bucket"
    assert (
        remediation.extract_s3_bucket_name("arn:aws:s3:::my-bucket/key") == "my-bucket"
    )


def test_extract_s3_bucket_name_invalid():
    with pytest.raises(ValueError, match="Could not extract bucket name"):
        remediation.extract_s3_bucket_name("invalid-arn")


def test_extract_kms_key_id():
    key_id = "12345678-1234-1234-1234-123456789012"
    assert (
        remediation.extract_kms_key_id(
            f"arn:aws:kms:us-east-1:123456789012:key/{key_id}"
        )
        == key_id
    )


def test_extract_kms_key_id_invalid():
    with pytest.raises(ValueError, match="Could not extract key ID"):
        remediation.extract_kms_key_id("invalid-arn")


@mock_aws
def test_handler_s3_wildcard_policy(mocker):
    s3_client = boto3.client("s3", config=BOTO_CONFIG)
    s3_client.create_bucket(Bucket=BUCKET_NAME)
    s3_client.put_bucket_policy(Bucket=BUCKET_NAME, Policy=json.dumps(WILDCARD_POLICY))

    mocker.patch("TightenResourcePolicy.get_organization_id", return_value=ORG_ID)

    result = remediation.handler(
        {"ResourceArn": BUCKET_ARN, "ResourceType": "s3"}, None
    )

    assert result["Status"] == "Success"
    assert result["StatementsModified"] == 1
    modified = result["ModifiedPolicy"]
    stmt = modified["Statement"][0]
    assert stmt["Principal"] == {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}
    assert stmt["Condition"]["StringEquals"]["aws:PrincipalOrgID"] == ORG_ID


@mock_aws
def test_handler_s3_no_wildcard(mocker):
    s3_client = boto3.client("s3", config=BOTO_CONFIG)
    s3_client.create_bucket(Bucket=BUCKET_NAME)
    s3_client.put_bucket_policy(
        Bucket=BUCKET_NAME, Policy=json.dumps(NO_WILDCARD_POLICY)
    )

    mocker.patch("TightenResourcePolicy.get_organization_id", return_value=None)

    # No-op run must raise so the finding is not auto-resolved.
    with pytest.raises(
        remediation.RemediationNotApplicableError,
        match="No wildcard principal found to remediate",
    ):
        remediation.handler({"ResourceArn": BUCKET_ARN, "ResourceType": "s3"}, None)


@mock_aws
def test_handler_s3_wildcard_plus_external_not_resolved(mocker):
    """Wildcard is tightened, but a residual cross-account principal must block auto-resolve."""
    s3_client = boto3.client("s3", config=BOTO_CONFIG)
    s3_client.create_bucket(Bucket=BUCKET_NAME)
    s3_client.put_bucket_policy(
        Bucket=BUCKET_NAME, Policy=json.dumps(WILDCARD_PLUS_EXTERNAL_POLICY)
    )

    mocker.patch("TightenResourcePolicy.get_organization_id", return_value=None)

    with pytest.raises(
        remediation.RemediationNotApplicableError,
        match="cannot safely remove automatically",
    ):
        remediation.handler({"ResourceArn": BUCKET_ARN, "ResourceType": "s3"}, None)

    # The wildcard fix is still applied even though the finding is not resolved.
    applied = json.loads(s3_client.get_bucket_policy(Bucket=BUCKET_NAME)["Policy"])
    assert applied["Statement"][0]["Principal"]["AWS"] == [
        f"arn:aws:iam::{ACCOUNT_ID}:root",
        "arn:aws:iam::999999999999:root",
    ]


def _build_external_principal_policy(
    condition: dict[str, Any] | None = None,
) -> remediation.ResourcePolicy:
    stmt: remediation.PolicyStatement = {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
    }
    if condition is not None:
        stmt["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [stmt]}


def test_has_external_principal_detects_cross_account():
    assert (
        remediation.has_external_principal(
            WILDCARD_PLUS_EXTERNAL_POLICY,
            account_id=ACCOUNT_ID,
            organization_id=ORG_ID,
        )
        is True
    )


def test_has_external_principal_same_account_only():
    assert (
        remediation.has_external_principal(
            NO_WILDCARD_POLICY, account_id=ACCOUNT_ID, organization_id=ORG_ID
        )
        is False
    )


def test_has_external_principal_org_scoped_not_flagged():
    """A cross-account principal scoped to the current org is not external."""
    policy = _build_external_principal_policy(
        {"StringEquals": {"aws:PrincipalOrgID": ORG_ID}}
    )
    assert (
        remediation.has_external_principal(
            policy, account_id=ACCOUNT_ID, organization_id=ORG_ID
        )
        is False
    )


def test_has_external_principal_wrong_org_still_flagged():
    """aws:PrincipalOrgID bound to a different org does not scope to us."""
    policy = _build_external_principal_policy(
        {"StringEquals": {"aws:PrincipalOrgID": "o-otherorg"}}
    )
    assert (
        remediation.has_external_principal(
            policy, account_id=ACCOUNT_ID, organization_id=ORG_ID
        )
        is True
    )


def test_has_external_principal_negation_operator_still_flagged():
    """A negation operator does not restrict access, so it is not scoping."""
    policy = _build_external_principal_policy(
        {"StringNotEquals": {"aws:PrincipalOrgID": ORG_ID}}
    )
    assert (
        remediation.has_external_principal(
            policy, account_id=ACCOUNT_ID, organization_id=ORG_ID
        )
        is True
    )


def test_has_external_principal_org_list_with_other_org_still_flagged():
    """A list value ORs the orgs, so [our-org, other-org] is not sole-org scoping."""
    policy = _build_external_principal_policy(
        {"StringEquals": {"aws:PrincipalOrgID": [ORG_ID, "o-otherorg"]}}
    )
    assert (
        remediation.has_external_principal(
            policy, account_id=ACCOUNT_ID, organization_id=ORG_ID
        )
        is True
    )


def test_has_external_principal_wildcarded_arn_flagged():
    """A wildcarded/unresolvable ARN must fail safe and be treated as external."""
    policy = _build_external_principal_policy()
    policy["Statement"][0]["Principal"] = {"AWS": "arn:aws:iam::*:root"}
    assert (
        remediation.has_external_principal(
            policy, account_id=ACCOUNT_ID, organization_id=ORG_ID
        )
        is True
    )


def test_has_external_principal_federated_flagged():
    """A Federated (external IdP) principal cannot be resolved, so it is external."""
    policy = _build_external_principal_policy()
    policy["Statement"][0]["Principal"] = {
        "Federated": "arn:aws:iam::999999999999:saml-provider/ExternalIdP"
    }
    assert (
        remediation.has_external_principal(
            policy, account_id=ACCOUNT_ID, organization_id=ORG_ID
        )
        is True
    )


def test_has_external_principal_canonical_user_flagged():
    """A CanonicalUser principal cannot be resolved to the owner, so it is external."""
    policy = _build_external_principal_policy()
    policy["Statement"][0]["Principal"] = {
        "CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
    }
    assert (
        remediation.has_external_principal(
            policy, account_id=ACCOUNT_ID, organization_id=ORG_ID
        )
        is True
    )


def test_has_external_principal_not_principal_flagged():
    """An Allow + NotPrincipal grants everyone except listed, so it is external."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
            }
        ],
    }
    assert (
        remediation.has_external_principal(
            policy, account_id=ACCOUNT_ID, organization_id=ORG_ID
        )
        is True
    )


def test_has_external_principal_org_scope_ignored_without_org():
    """Without a known org, an aws:PrincipalOrgID condition cannot be trusted."""
    policy = _build_external_principal_policy(
        {"StringEquals": {"aws:PrincipalOrgID": ORG_ID}}
    )
    assert (
        remediation.has_external_principal(
            policy, account_id=ACCOUNT_ID, organization_id=None
        )
        is True
    )


@mock_aws
def test_handler_s3_wildcard_plus_external_org_scoped_resolves(mocker):
    """When org-scoping is applied, the residual cross-account principal is not external."""
    s3_client = boto3.client("s3", config=BOTO_CONFIG)
    s3_client.create_bucket(Bucket=BUCKET_NAME)
    s3_client.put_bucket_policy(
        Bucket=BUCKET_NAME, Policy=json.dumps(WILDCARD_PLUS_EXTERNAL_POLICY)
    )

    mocker.patch("TightenResourcePolicy.get_organization_id", return_value=ORG_ID)

    result = remediation.handler(
        {"ResourceArn": BUCKET_ARN, "ResourceType": "s3"}, None
    )

    assert result["Status"] == "Success"
    assert result["StatementsModified"] == 1
    stmt = result["ModifiedPolicy"]["Statement"][0]
    assert stmt["Condition"]["StringEquals"]["aws:PrincipalOrgID"] == ORG_ID


@mock_aws
def test_handler_s3_deny_not_modified(mocker):
    """Handler should not modify Deny statements with wildcard principals."""
    s3_client = boto3.client("s3", config=BOTO_CONFIG)
    s3_client.create_bucket(Bucket=BUCKET_NAME)
    s3_client.put_bucket_policy(
        Bucket=BUCKET_NAME, Policy=json.dumps(DENY_WILDCARD_POLICY)
    )

    mocker.patch("TightenResourcePolicy.get_organization_id", return_value=ORG_ID)

    result = remediation.handler(
        {"ResourceArn": BUCKET_ARN, "ResourceType": "s3"}, None
    )

    assert result["Status"] == "Success"
    assert result["StatementsModified"] == 1
    modified = result["ModifiedPolicy"]
    deny_stmt = modified["Statement"][0]
    assert deny_stmt["Principal"] == "*"  # Deny unchanged


def test_handler_unsupported_resource_type():
    """Handler should fail fast before making any API calls for unsupported types."""
    with pytest.raises(ValueError, match="Unsupported resource type"):
        remediation.handler(
            {
                "ResourceArn": "arn:aws:lambda:us-east-1:123:function:test",
                "ResourceType": "lambda",
            },
            None,
        )


@mock_aws
def test_handler_kms_wildcard_policy(mocker):
    """End-to-end handler test for KMS key with wildcard principal."""
    kms_client = boto3.client("kms", config=BOTO_CONFIG)
    key = kms_client.create_key()
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]

    wildcard_kms_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPublic",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "kms:Decrypt",
                "Resource": key_arn,
            }
        ],
    }
    kms_client.put_key_policy(
        KeyId=key_id, PolicyName="default", Policy=json.dumps(wildcard_kms_policy)
    )

    mocker.patch("TightenResourcePolicy.get_organization_id", return_value=ORG_ID)

    result = remediation.handler({"ResourceArn": key_arn, "ResourceType": "kms"}, None)

    assert result["Status"] == "Success"
    assert result["StatementsModified"] == 1
    modified = result["ModifiedPolicy"]
    stmt = modified["Statement"][0]
    assert stmt["Principal"] == {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"}
    assert stmt["Condition"]["StringEquals"]["aws:PrincipalOrgID"] == ORG_ID


@mock_aws
def test_get_organization_id_returns_org_id():
    """get_organization_id returns the org ID when account is in an organization."""
    org_client = boto3.client("organizations", config=BOTO_CONFIG)
    org_client.create_organization(FeatureSet="ALL")
    result = remediation.get_organization_id()
    assert result is not None
    assert result.startswith("o-")


@mock_aws
def test_get_organization_id_not_in_org(mocker):
    """get_organization_id returns None when account is not in an organization."""
    from botocore.exceptions import ClientError

    mocker.patch.object(
        remediation,
        "connect_to_service",
        return_value=mocker.Mock(
            describe_organization=mocker.Mock(
                side_effect=ClientError(
                    {
                        "Error": {
                            "Code": "AWSOrganizationsNotInUseException",
                            "Message": "",
                        }
                    },
                    "DescribeOrganization",
                )
            )
        ),
    )
    assert remediation.get_organization_id() is None


@mock_aws
def test_get_organization_id_access_denied(mocker):
    """get_organization_id returns None on AccessDeniedException (non-retryable)."""
    from botocore.exceptions import ClientError

    mocker.patch.object(
        remediation,
        "connect_to_service",
        return_value=mocker.Mock(
            describe_organization=mocker.Mock(
                side_effect=ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": ""}},
                    "DescribeOrganization",
                )
            )
        ),
    )
    assert remediation.get_organization_id() is None


@mock_aws
def test_get_organization_id_throttling_reraises(mocker):
    """get_organization_id re-raises retryable errors like ThrottlingException."""
    from botocore.exceptions import ClientError

    mocker.patch.object(
        remediation,
        "connect_to_service",
        return_value=mocker.Mock(
            describe_organization=mocker.Mock(
                side_effect=ClientError(
                    {"Error": {"Code": "ThrottlingException", "Message": ""}},
                    "DescribeOrganization",
                )
            )
        ),
    )
    with pytest.raises(ClientError, match="ThrottlingException"):
        remediation.get_organization_id()
