# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import re
from typing import Any, Literal, TypedDict

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import ClientError

BOTO_CONFIG = Config(retries={"mode": "standard"})

VALID_PARTITIONS = {"aws", "aws-cn", "aws-us-gov"}


class RemediationNotApplicableError(Exception):
    """Raised when the finding has no remediable condition for this runbook."""


ResourceType = Literal["s3", "kms"]
SUPPORTED_RESOURCE_TYPES = {"s3", "kms"}

ServiceName = Literal["s3", "kms", "organizations", "sts"]

# IAM policy principal: either "*" or {"AWS": "arn:..."} or {"AWS": ["arn:...", ...]}
# May also contain "Service" key but those are never wildcards.
Principal = str | dict[str, str | list[str]]


class PolicyStatement(TypedDict, total=False):
    Sid: str
    Effect: str
    Principal: Principal
    NotPrincipal: Principal
    Action: str | list[str]
    Resource: str | list[str]
    Condition: dict[str, Any]


class ResourcePolicy(TypedDict):
    Version: str
    Statement: list[PolicyStatement]


class HandlerEvent(TypedDict):
    ResourceArn: str
    ResourceType: ResourceType


class RemediationResult(TypedDict):
    Status: str
    Message: str
    OriginalPolicy: ResourcePolicy
    ModifiedPolicy: ResourcePolicy
    StatementsModified: int


def connect_to_service(service: ServiceName) -> BaseClient:
    return boto3.client(service, config=BOTO_CONFIG)


def get_organization_id() -> str | None:
    """Query AWS Organizations API to get the Organization ID, if any.

    Returns None if the account is not in an organization or if the API call
    fails (e.g., access denied, throttling). Org membership is an optional
    enhancement — remediation proceeds without the PrincipalOrgID condition.
    """
    RETRYABLE_ERROR_CODES = {
        "ThrottlingException",
        "ServiceUnavailableException",
        "TooManyRequestsException",
    }

    org_client = connect_to_service("organizations")
    try:
        response = org_client.describe_organization()
        return response["Organization"]["Id"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AWSOrganizationsNotInUseException":
            return None
        if code in RETRYABLE_ERROR_CODES:
            raise
        # SSM inlines this script in the automation document, so the standard
        # Python logging module is not available. print() goes to SSM execution
        # output which operators can inspect via the SSM console or API.
        print(
            f"WARNING: Proceeding without PrincipalOrgID condition. "
            f"Could not retrieve Organization ID ({code}): {e}"
        )
        return None


def get_resource_policy(
    resource_arn: str, resource_type: ResourceType, *, account_id: str
) -> ResourcePolicy:
    """Retrieve the current resource policy for the given resource."""
    if resource_type == "s3":
        bucket_name = extract_s3_bucket_name(resource_arn)
        s3_client = connect_to_service("s3")
        try:
            # ExpectedBucketOwner asserts the bucket is still owned by the
            # remediation account. S3 ARNs carry no account id, so without this
            # a bucket deleted and re-created in an attacker account (bucket
            # sniping) could have its policy read/tightened by ASR (CWE-283).
            response = s3_client.get_bucket_policy(
                Bucket=bucket_name, ExpectedBucketOwner=account_id
            )
            return json.loads(response["Policy"])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                raise ValueError(f"No bucket policy found for {bucket_name}") from e
            raise
    elif resource_type == "kms":
        key_id = extract_kms_key_id(resource_arn)
        kms_client = connect_to_service("kms")
        response = kms_client.get_key_policy(KeyId=key_id, PolicyName="default")
        return json.loads(response["Policy"])
    else:
        raise ValueError(f"Unsupported resource type: {resource_type}")


def put_resource_policy(
    resource_arn: str,
    resource_type: ResourceType,
    policy: ResourcePolicy,
    *,
    account_id: str,
) -> None:
    """Apply the modified resource policy."""
    policy_json = json.dumps(policy)
    if resource_type == "s3":
        bucket_name = extract_s3_bucket_name(resource_arn)
        s3_client = connect_to_service("s3")
        # ExpectedBucketOwner guards against writing the tightened policy to a
        # sniped/re-created bucket now owned by another account (CWE-283).
        s3_client.put_bucket_policy(
            Bucket=bucket_name, Policy=policy_json, ExpectedBucketOwner=account_id
        )
    elif resource_type == "kms":
        key_id = extract_kms_key_id(resource_arn)
        kms_client = connect_to_service("kms")
        kms_client.put_key_policy(
            KeyId=key_id, PolicyName="default", Policy=policy_json
        )
    else:
        raise ValueError(f"Unsupported resource type: {resource_type}")


def extract_s3_bucket_name(resource_arn: str) -> str:
    """Extract bucket name from S3 ARN."""
    # The bucket-name group uses [^/]+ (not .+?) so it cannot overlap with the
    # optional /object-key suffix. This removes the ambiguous backtracking the
    # lazy (.+?)(?:/.*)? form allowed and is also more correct: S3 bucket names
    # never contain a slash.
    match = re.match(
        r"^arn:(?:aws|aws-cn|aws-us-gov):s3:::([^/]+)(?:/.*)?$", resource_arn
    )
    if match:
        return match.group(1)
    raise ValueError(f"Could not extract bucket name from ARN: {resource_arn}")


def extract_kms_key_id(resource_arn: str) -> str:
    """Extract key ID from KMS ARN."""
    match = re.match(
        r"^arn:(?:aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:\d{12}:key/(.+)$",
        resource_arn,
    )
    if match:
        return match.group(1)
    raise ValueError(f"Could not extract key ID from ARN: {resource_arn}")


def is_wildcard_principal(principal: Principal) -> bool:
    """Check if a principal is a wildcard."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws_val = principal.get("AWS")
        if aws_val == "*":
            return True
        if isinstance(aws_val, list) and "*" in aws_val:
            return True
    return False


def replace_wildcard_principal(
    principal: Principal, *, account_id: str, partition: str
) -> dict[str, str | list[str]]:
    """Replace wildcard principal with the owning account ID. Always returns a new dict."""
    root_arn = f"arn:{partition}:iam::{account_id}:root"
    if principal == "*":
        return {"AWS": root_arn}
    if isinstance(principal, dict):
        result = dict(principal)
        aws_val = result.get("AWS")
        if aws_val == "*":
            result["AWS"] = root_arn
        elif isinstance(aws_val, list):
            result["AWS"] = [root_arn if p == "*" else p for p in aws_val]
        return result
    raise ValueError(f"Unexpected principal value: {principal}")


def add_org_condition(statement: PolicyStatement, organization_id: str) -> None:
    """Add aws:PrincipalOrgID condition to a statement."""
    if "Condition" not in statement:
        statement["Condition"] = {}
    condition = statement["Condition"]
    if "StringEquals" not in condition:
        condition["StringEquals"] = {}
    condition["StringEquals"]["aws:PrincipalOrgID"] = organization_id


def tighten_policy(
    policy: ResourcePolicy,
    *,
    account_id: str,
    organization_id: str | None,
    partition: str,
) -> int:
    """Tighten a resource policy by replacing wildcard principals in Allow statements.

    Mutates ``policy`` in place — the caller is responsible for passing a deep copy
    if the original must be preserved (see ``handler``).

    Deny statements are intentionally skipped — modifying a Deny with Principal: "*"
    would narrow the deny scope and could make the resource more accessible.
    """
    statements_modified = 0
    statements = policy.get("Statement", [])

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")
        if principal is None:
            continue

        if is_wildcard_principal(principal):
            statement["Principal"] = replace_wildcard_principal(
                principal, account_id=account_id, partition=partition
            )
            if organization_id:
                add_org_condition(statement, organization_id)
            statements_modified += 1

    return statements_modified


def _principal_account(value: str) -> str | None:
    """Return the AWS account id for a principal value (bare id or ARN), else None."""
    if re.fullmatch(r"\d{12}", value):
        return value
    match = re.match(r"^arn:[^:]+:[^:]*:[^:]*:(\d{12}):", value)
    return match.group(1) if match else None


# Positive string-match operators AWS evaluates as a restrictive equality/like.
# Negation operators (StringNotEquals*) and Null do not restrict access.
# ForAllValues:* is excluded: it is satisfied by an absent/empty key, so it does
# not guarantee org membership.
_ORG_SCOPING_OPERATORS = {
    "stringequals",
    "stringequalsignorecase",
    "stringlike",
    "foranyvalue:stringequals",
    "foranyvalue:stringlike",
}


def _condition_binds_org(operator_values: dict[str, Any], organization_id: str) -> bool:
    """True if a condition operator map binds aws:PrincipalOrgID to organization_id."""
    for key, value in operator_values.items():
        if key.lower() != "aws:principalorgid":
            continue
        # Require the org to be the sole value: a list ORs the values, so
        # [our-org, other-org] would also grant the other org.
        values = value if isinstance(value, list) else [value]
        if values == [organization_id]:
            return True
    return False


def _statement_is_scoped_to_org(
    statement: PolicyStatement, organization_id: str | None
) -> bool:
    """True if the statement restricts principals to the current org via aws:PrincipalOrgID.

    Only a positive string-match operator bound to the current organization_id counts —
    negation operators and other-org values are not trusted. Mirrors the condition that
    tighten_policy adds.
    """
    if organization_id is None:
        return False
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return False
    for operator, operator_values in condition.items():
        if (
            operator.lower() in _ORG_SCOPING_OPERATORS
            and isinstance(operator_values, dict)
            and _condition_binds_org(operator_values, organization_id)
        ):
            return True
    return False


def _principal_aws_values(principal: Principal) -> list[str]:
    """AWS principal values from a statement principal ("*" included), else []."""
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        aws_value = principal.get("AWS")
        if aws_value is None:
            return []
        return aws_value if isinstance(aws_value, list) else [aws_value]
    return []


def _is_external_principal_value(value: str, account_id: str) -> bool:
    """True if a value is a wildcard, a different account, or cannot be resolved.

    Fail safe: a wildcarded/malformed ARN or otherwise unparseable value (account
    is None) is treated as external so it is never silently auto-resolved.
    """
    if "*" in value:
        return True
    return _principal_account(value) != account_id


# Principal keys that reference an entity outside the owning account and cannot be
# resolved/tightened here — treated as external (fail safe).
_EXTERNAL_PRINCIPAL_KEYS = ("Federated", "CanonicalUser")


def _statement_grants_external_access(
    statement: PolicyStatement, account_id: str
) -> bool:
    """True if the Allow statement grants a wildcard or cross-account principal."""
    # Allow + NotPrincipal grants everyone except the listed principals — effectively
    # broad/cross-account access this runbook cannot safely rewrite.
    if statement.get("NotPrincipal") is not None:
        return True
    principal = statement.get("Principal")
    if principal is None:
        return False
    # Federated (external IdP) and CanonicalUser principals cannot be resolved to the
    # owning account; fail safe and treat them as external / not safely remediable.
    if isinstance(principal, dict) and any(
        key in principal for key in _EXTERNAL_PRINCIPAL_KEYS
    ):
        return True
    return any(
        _is_external_principal_value(value, account_id)
        for value in _principal_aws_values(principal)
    )


def has_external_principal(
    policy: ResourcePolicy, *, account_id: str, organization_id: str | None
) -> bool:
    """True if any Allow statement still grants a cross-account or wildcard AWS principal.

    Wildcard tightening only handles "*"; a policy can also grant a specific external
    account (a common IAMAccessAnalyzer.ExternalAccess trigger) that this runbook does
    not remediate. Statements scoped to the current org via aws:PrincipalOrgID are not
    external. Only AWS principals are inspected (Service/Federated are out of scope).
    """
    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        if _statement_is_scoped_to_org(statement, organization_id):
            continue
        if _statement_grants_external_access(statement, account_id):
            return True
    return False


def handler(event: HandlerEvent, _: None) -> RemediationResult:
    """Main handler for the TightenResourcePolicy remediation runbook."""
    resource_arn = event["ResourceArn"]
    resource_type: ResourceType = event["ResourceType"]

    # Fail fast on unsupported resource types before making any API calls
    if resource_type not in SUPPORTED_RESOURCE_TYPES:
        raise ValueError(
            f"Unsupported resource type: {resource_type}. "
            f"Expected one of: {SUPPORTED_RESOURCE_TYPES}"
        )

    # Extract and validate partition from resource ARN
    arn_parts = resource_arn.split(":")
    if len(arn_parts) < 2:
        raise ValueError(f"Malformed ARN (no partition): {resource_arn}")
    partition = arn_parts[1]
    if partition not in VALID_PARTITIONS:
        raise ValueError(
            f"Invalid partition '{partition}' in ARN: {resource_arn}. "
            f"Expected one of: {VALID_PARTITIONS}"
        )

    account_id = boto3.client("sts", config=BOTO_CONFIG).get_caller_identity()[
        "Account"
    ]

    organization_id = get_organization_id()

    original_policy = get_resource_policy(
        resource_arn, resource_type, account_id=account_id
    )
    modified_policy = json.loads(json.dumps(original_policy))

    statements_modified = tighten_policy(
        modified_policy,
        account_id=account_id,
        organization_id=organization_id,
        partition=partition,
    )

    # Apply whatever wildcard tightening we could before deciding on the finding status.
    if statements_modified > 0:
        put_resource_policy(
            resource_arn, resource_type, modified_policy, account_id=account_id
        )
        # Verify semantically by re-fetching and confirming no wildcard principal
        # remains. AWS canonicalizes policies on read (collapsing single-element lists,
        # expanding a bare account id to an ARN, etc.), so a byte comparison against the
        # locally-built policy would spuriously fail even when the write succeeded.
        verified_policy = get_resource_policy(
            resource_arn, resource_type, account_id=account_id
        )
        residual_wildcards = tighten_policy(
            json.loads(json.dumps(verified_policy)),
            account_id=account_id,
            organization_id=organization_id,
            partition=partition,
        )
        if residual_wildcards > 0:
            raise RuntimeError(
                f"Policy verification failed: wildcard principals still present after "
                f"tightening. Resource: {resource_arn}"
            )
    else:
        verified_policy = original_policy

    # Do not auto-resolve if a non-wildcard external (cross-account) principal remains.
    # This runbook only rewrites wildcard ("*") principals; it cannot safely remove a
    # grant to a specific external account, since that access may be intentional (e.g. a
    # partner integration). Leave the finding open for a human to confirm and remediate.
    #
    # The control runbook (SC_IAMAccessAnalyzer.ExternalAccess) treats this failure as
    # "skip the RESOLVED update" (its Remediation step onFailure jumps to
    # GetRemediationDetails and ends). SSM does not revert the put_resource_policy above,
    # so the wildcard tightening we already applied intentionally persists.
    if has_external_principal(
        modified_policy, account_id=account_id, organization_id=organization_id
    ):
        raise RemediationNotApplicableError(
            f"Policy still grants access to a specific external account that this runbook "
            f"cannot safely remove automatically; manual review required: {resource_arn}"
        )

    if statements_modified == 0:
        # No wildcard principal to rewrite; raise so the finding is not auto-resolved.
        raise RemediationNotApplicableError(
            f"No wildcard principal found to remediate: {resource_arn}"
        )

    return {
        "Status": "Success",
        "Message": f"Tightened {statements_modified} policy statement(s)",
        "OriginalPolicy": original_policy,
        "ModifiedPolicy": verified_policy,
        "StatementsModified": statements_modified,
    }
