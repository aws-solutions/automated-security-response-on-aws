# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# NOTE: Comments are kept minimal to reduce CloudFormation template size.
# This script is embedded inline in the control runbook SSM document.
import re
from typing import TypedDict


class AffectedObject(TypedDict):
    Type: str
    Id: str
    OutputKey: str


class ParseResult(TypedDict):
    finding_id: str
    product_arn: str
    account_id: str
    resource_arn: str
    resource_type: str
    resource_region: str
    object: AffectedObject


class AsffResource(TypedDict, total=False):
    Type: str
    Id: str
    Region: str


class AsffFinding(TypedDict, total=False):
    """Subset of ASFF finding fields accessed by this parser.

    The full ASFF schema has 100+ fields; only the keys this script reads
    are modeled here. total=False because Security Hub may omit optional fields.
    """

    Id: str
    ProductArn: str
    AwsAccountId: str
    ProductFields: dict[str, str]
    Resources: list[AsffResource]


class ParseInput(TypedDict):
    Finding: AsffFinding


RESOURCE_TYPE_MAP = {
    "AwsS3Bucket": "s3",
    "AwsKmsKey": "kms",
}


def _resolve_account_id(finding: AsffFinding) -> str:
    # For an organization analyzer, ASFF AwsAccountId is the administrator
    # account while ProductFields.ResourceOwnerAccount names the account the
    # resource lives in. Prefer the resource owner so the remediation targets
    # the correct account; fall back to AwsAccountId (e.g. per-account analyzer).
    resource_owner_account = finding.get("ProductFields", {}).get(
        "ResourceOwnerAccount", ""
    )
    if resource_owner_account:
        if not re.match(r"^\d{12}$", resource_owner_account):
            raise ValueError(f"Invalid ResourceOwnerAccount: {resource_owner_account}")
        return resource_owner_account

    account_id = finding.get("AwsAccountId", "")
    if not re.match(r"^\d{12}$", account_id):
        raise ValueError(f"Invalid AwsAccountId: {account_id}")
    return account_id


def parse_event(event: ParseInput, _: None) -> ParseResult:
    """Parse ASFF finding to extract resource details."""
    finding = event["Finding"]
    finding_id = finding.get("Id", "")
    product_arn = finding.get("ProductArn", "")
    account_id = _resolve_account_id(finding)

    resources = finding.get("Resources", [])
    if not resources:
        raise ValueError("No resources found in finding")

    resource = resources[0]
    resource_id = resource.get("Id", "")
    resource_type_asff = resource.get("Type", "")

    # Validate resource ARN format (consistent with resourceIdRegex in the
    # control runbook CDK construct, which is not available at SSM runtime)
    if not re.match(r"^arn:(?:aws|aws-cn|aws-us-gov):.+", resource_id):
        raise ValueError(f"Invalid resource ARN: {resource_id}")

    resource_type = RESOURCE_TYPE_MAP.get(resource_type_asff)
    if not resource_type:
        raise ValueError(
            f"Unsupported resource type: {resource_type_asff}. "
            f"Supported types: {list(RESOURCE_TYPE_MAP.keys())}"
        )

    resource_region = resource.get("Region", "")
    if not resource_region:
        arn_match = re.match(
            r"^arn:(?:aws|aws-cn|aws-us-gov):[a-zA-Z0-9]+:"
            r"([a-z]{2}(?:-gov)?-[a-z]+-\d):",
            resource_id,
        )
        if arn_match:
            resource_region = arn_match.group(1)
        elif resource_type != "s3":
            # S3 ARNs don't contain a region, but KMS ARNs do
            raise ValueError(
                f"Could not determine region for {resource_type_asff} resource: {resource_id}"
            )
        # S3 is a global service — region is not required in the ARN and the
        # remediation runbook (TightenResourcePolicy) operates on the bucket
        # name only, so an empty region is valid and expected here.

    return {
        "finding_id": finding_id,
        "product_arn": product_arn,
        "account_id": account_id,
        "resource_arn": resource_id,
        "resource_type": resource_type,
        "resource_region": resource_region,
        "object": {
            "Type": resource_type_asff,
            "Id": resource_id,
            "OutputKey": "Remediation.Output",
        },
    }
