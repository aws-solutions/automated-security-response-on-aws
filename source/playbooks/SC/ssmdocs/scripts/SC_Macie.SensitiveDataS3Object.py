# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# NOTE: Comments are kept minimal to reduce CloudFormation template size.
# This script is embedded inline in the control runbook SSM document.
import re
from typing import Literal, NamedTuple, Required, TypedDict, TypeGuard

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import ClientError

BOTO_CONFIG = Config(retries={"mode": "standard"})

Status = Literal["SUCCESS", "FAILED"]
WorkflowStatus = Literal["IN_PROGRESS", "NOTIFIED", "RESOLVED", "NEW"]

# Security Hub BatchUpdateFindings.Note.Text rejects payloads over 512 chars.
SECURITY_HUB_NOTE_MAX_LEN = 512

_ServiceName = Literal["s3", "securityhub"]

# Per-invocation boto3 session and client cache. The runbook's
# AutomationAssumeRole (Orchestrator-Member for multi-service controls) does
# not carry s3:PutBucketPublicAccessBlock or securityhub:BatchUpdateFindings;
# those live on the per-control role (RemediationRoleName). parse_event assumes
# that role once and _client(...) returns clients bound to it. Unit tests call
# the core directly without a session, so _client falls back to module-level
# boto3 and existing @patch("boto3.client", ...) mocks keep working.
_SESSION: "boto3.session.Session | None" = None
_CLIENT_CACHE: dict[_ServiceName, BaseClient] = {}


def _reset_clients() -> None:
    _CLIENT_CACHE.clear()


def _client(service: _ServiceName) -> BaseClient:
    cached = _CLIENT_CACHE.get(service)
    if cached is not None:
        return cached
    if _SESSION is not None:
        client = _SESSION.client(service, config=BOTO_CONFIG)
    else:
        client = boto3.client(service, config=BOTO_CONFIG)
    # boto3's client factory is typed as returning Any without service stubs
    # (none are bundled into the inline runbook). Reading the value back from
    # the BaseClient-typed cache yields the declared return type without a cast.
    _CLIENT_CACHE[service] = client
    return _CLIENT_CACHE[service]


class RemediationSessionError(RuntimeError):
    """Raised when assuming the per-control remediation role fails.

    A RuntimeError (not ValueError) so it is not swallowed by the
    validation-error handling in _execute_remediation and instead fails the
    SSM execution.
    """


def _init_remediation_session(*, role_name: str) -> None:
    """Assume the per-control role and cache the session for _client(...).

    Account id and partition are derived from the caller identity (the
    runbook already runs in the target account), mirroring the Inspector
    runbook.
    """
    global _SESSION
    sts = boto3.client("sts", config=BOTO_CONFIG)
    try:
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        caller_arn = identity["Arn"]
        partition = caller_arn.split(":")[1] if caller_arn.startswith("arn:") else "aws"
        role_arn = f"arn:{partition}:iam::{account_id}:role/{role_name}"
        creds = sts.assume_role(
            RoleArn=role_arn, RoleSessionName="ASR-Macie-SensitiveDataS3Object"
        )["Credentials"]
    except ClientError as e:
        raise RemediationSessionError(
            f"Failed to assume per-control remediation role {role_name!r}: {e}"
        ) from e
    _SESSION = boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    _reset_clients()


class AffectedObject(TypedDict):
    Type: str
    Id: str
    OutputKey: str


class ParseResult(TypedDict):
    finding_id: str
    product_arn: str
    account_id: str
    resource_region: str
    bucket_name: str
    status: Status
    message: str
    object: AffectedObject


# OCSF TypedDicts — only the fields this script reads
class FindingInfo(TypedDict, total=False):
    uid: str
    types: list[str]


class ProductInfo(TypedDict, total=False):
    uid: str


class Metadata(TypedDict, total=False):
    product: ProductInfo


class AccountInfo(TypedDict, total=False):
    uid: str


class OcsfOwner(TypedDict, total=False):
    account: AccountInfo


class OcsfCloud(TypedDict, total=False):
    account: AccountInfo
    region: str


class OcsfResource(TypedDict, total=False):
    uid: str
    uid_alt: str
    type: str
    region: str
    cloud_partition: str
    owner: OcsfOwner
    account: AccountInfo


class OcsfFinding(TypedDict, total=False):
    finding_info: FindingInfo
    metadata: Metadata
    resources: list[OcsfResource]
    cloud: OcsfCloud


# ASFF TypedDicts — only the fields this script reads
class AsffResource(TypedDict, total=False):
    Id: str
    Type: str
    Region: str


class AsffFinding(TypedDict, total=False):
    Id: Required[str]
    AwsAccountId: Required[str]
    Resources: Required[list[AsffResource]]
    ProductArn: str
    Region: str


# A finding reaches the runbook either as OCSF (native ingestion) or ASFF
# (findings/action API replay of the persisted representation).
InputFinding = OcsfFinding | AsffFinding


class ParseInput(TypedDict, total=False):
    Finding: Required[InputFinding]
    SSMDocName: Required[str]
    RemediationRoleName: Required[str]


class ValidatedFinding(NamedTuple):
    finding_id: str
    product_arn: str
    account_id: str
    resource_region: str
    partition: str
    bucket_name: str


def _is_asff_finding(finding: InputFinding) -> TypeGuard[AsffFinding]:
    """ASFF carries Id/AwsAccountId/Resources; OCSF carries finding_info/resources."""
    return "Id" in finding and "AwsAccountId" in finding and "Resources" in finding


def _is_ocsf_finding(finding: InputFinding) -> TypeGuard[OcsfFinding]:
    return "finding_info" in finding or "resources" in finding


def _bucket_name_from_arn(arn: str) -> str:
    """Return the bucket name from an S3 ARN (arn:...:s3:::bucket[/key]), or ""."""
    match = re.match(r"arn:[^:]*:s3:::([^/]+)", arn or "")
    return match.group(1) if match else ""


def _resolve_ocsf_account_id(*, finding: OcsfFinding, resource: OcsfResource) -> str:
    """Resolve the 12-digit account id from a V2/V1 OCSF finding.

    Real Security Hub V2 OCSF Data Security findings carry the account at
    ``cloud.account.uid`` and ``resources[0].owner.account.uid``; the resource
    has no ``account`` field. Fall back to ``resources[0].account.uid`` for
    callers that put it directly on the resource.
    """
    return (
        finding.get("cloud", {}).get("account", {}).get("uid", "")
        or resource.get("owner", {}).get("account", {}).get("uid", "")
        or resource.get("account", {}).get("uid", "")
    )


def _ocsf_bucket_name_from_bucket_resource(resource: OcsfResource) -> str:
    """Return the bucket name from an OCSF ``AWS::S3::Bucket`` resource.

    The bucket resource's ``uid`` is the bare bucket name; ``uid_alt`` is the
    bucket ARN. Returns "" when the resource is not a bucket resource or carries
    no usable name.
    """
    resource_type = resource.get("type", "")
    if not (resource_type.endswith("S3::Bucket") or resource_type == "AwsS3Bucket"):
        return ""
    uid = resource.get("uid", "") or ""
    if uid and not uid.startswith("arn:"):
        return uid
    for candidate in (resource.get("uid_alt", ""), uid):
        name = _bucket_name_from_arn(candidate or "")
        if name:
            return name
    return ""


def _ocsf_bucket_name_from_any_arn(resources: list[OcsfResource]) -> str:
    """Fallback: return the first bucket name derivable from any S3 ARN in the resources."""
    for resource in resources:
        for candidate in (resource.get("uid_alt", ""), resource.get("uid", "")):
            name = _bucket_name_from_arn(candidate or "")
            if name:
                return name
    return ""


def _resolve_ocsf_bucket_name(*, resources: list[OcsfResource]) -> str:
    """Resolve the S3 bucket name from OCSF resources.

    Real Macie findings list the S3 object as resources[0] (uid is the bare
    object key, e.g. "test-data.txt") and the bucket as a separate
    AWS::S3::Bucket resource whose uid is the bare bucket name (uid_alt is the
    bucket ARN). Prefer the bucket resource; fall back to any S3 ARN in the
    resources.
    """
    for resource in resources:
        name = _ocsf_bucket_name_from_bucket_resource(resource)
        if name:
            return name
    fallback = _ocsf_bucket_name_from_any_arn(resources)
    if fallback:
        return fallback
    raise ValueError("Could not resolve S3 bucket name from OCSF finding resources")


def _validate_finding(*, finding: OcsfFinding) -> ValidatedFinding:
    """Validate an OCSF finding and extract key fields."""
    finding_info = finding.get("finding_info", {})
    finding_id = finding_info.get("uid", "")
    metadata = finding.get("metadata", {})
    product = metadata.get("product", {})
    product_arn = product.get("uid", "")

    resources = finding.get("resources", [])
    if not resources:
        raise ValueError("No resources found in OCSF finding")

    resource = resources[0]
    partition = resource.get("cloud_partition", "aws")
    resource_region = resource.get("region", "") or finding.get("cloud", {}).get(
        "region", ""
    )
    account_id = _resolve_ocsf_account_id(finding=finding, resource=resource)

    if not re.match(r"^\d{12}$", account_id):
        raise ValueError(f"Invalid account ID: {account_id}")

    if not re.match(r"^[a-z]{2}(-gov)?-[a-z]+-\d$", resource_region):
        raise ValueError(f"Invalid or missing resource region: {resource_region!r}")

    if not finding_id:
        raise ValueError("Missing finding_info.uid in OCSF finding")

    if not product_arn:
        raise ValueError("Missing metadata.product.uid in OCSF finding")

    bucket_name = _resolve_ocsf_bucket_name(resources=resources)
    return ValidatedFinding(
        finding_id, product_arn, account_id, resource_region, partition, bucket_name
    )


def _resolve_asff_bucket_name(*, resources: list[AsffResource]) -> str:
    """Resolve the S3 bucket name from ASFF resources.

    A native S3 finding carries the bucket as an arn:aws:s3:::bucket[/key] Id. A
    Macie finding replayed through the findings/action API preserves the
    OCSF-origin values, listing the bucket as an AWS::S3::Bucket resource whose
    Id is the bare bucket name. Prefer the bucket resource (bare name or ARN);
    fall back to any S3 ARN in the resources.
    """
    for resource in resources:
        resource_type = resource.get("Type", "")
        if resource_type.endswith("S3::Bucket") or resource_type == "AwsS3Bucket":
            resource_id = resource.get("Id", "") or ""
            if resource_id and not resource_id.startswith("arn:"):
                return resource_id
            name = _bucket_name_from_arn(resource_id)
            if name:
                return name
    for resource in resources:
        name = _bucket_name_from_arn(resource.get("Id", ""))
        if name:
            return name
    raise ValueError("Could not resolve S3 bucket name from ASFF finding resources")


def _validate_asff_finding(*, finding: AsffFinding) -> ValidatedFinding:
    """Validate an ASFF finding and extract key fields.

    Keep field extraction in sync with the OCSF path above.
    """
    finding_id = finding.get("Id", "")
    product_arn = finding.get("ProductArn", "")
    account_id = finding.get("AwsAccountId", "")
    region = finding.get("Region", "")

    resources = finding.get("Resources", [])
    if not resources:
        raise ValueError("No resources found in ASFF finding")

    resource = resources[0]
    resource_id = resource.get("Id", "")
    resource_region = resource.get("Region", region)

    partition = "aws"
    if resource_id.startswith("arn:"):
        parts = resource_id.split(":", 3)
        if len(parts) >= 2 and parts[1]:
            partition = parts[1]

    if not re.match(r"^\d{12}$", account_id):
        raise ValueError(f"Invalid account ID: {account_id}")

    if not finding_id:
        raise ValueError("Missing Id in ASFF finding")

    if not product_arn:
        raise ValueError("Missing ProductArn in ASFF finding")

    bucket_name = _resolve_asff_bucket_name(resources=resources)

    return ValidatedFinding(
        finding_id, product_arn, account_id, resource_region, partition, bucket_name
    )


def _enable_public_access_block(*, bucket_name: str, account_id: str) -> None:
    """Enable all four S3 Block Public Access settings on the bucket."""
    s3 = _client("s3")
    # _client returns BaseClient, which has no service-specific methods because
    # no boto3 service stubs are bundled into the inline runbook; the call is
    # valid at runtime, so the attr-defined check is suppressed here.
    # ExpectedBucketOwner asserts the bucket is still owned by the finding's
    # account, so a bucket sniped/re-created in another account cannot have its
    # public-access block silently reconfigured by ASR (CWE-283).
    s3.put_public_access_block(  # type: ignore[attr-defined]
        Bucket=bucket_name,
        ExpectedBucketOwner=account_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


def _truncate_note(text: str) -> str:
    if len(text) <= SECURITY_HUB_NOTE_MAX_LEN:
        return text
    suffix = "..."
    return text[: SECURITY_HUB_NOTE_MAX_LEN - len(suffix)] + suffix


def _update_security_hub_finding(
    *,
    finding_id: str,
    product_arn: str,
    workflow_status: WorkflowStatus,
    note_text: str,
    ssm_doc_name: str,
) -> None:
    """Update Security Hub finding workflow status and note."""
    security_hub = _client("securityhub")
    # BaseClient has no batch_update_findings without service stubs (not bundled
    # into the inline runbook); the call is valid at runtime.
    security_hub.batch_update_findings(  # type: ignore[attr-defined]
        FindingIdentifiers=[{"Id": finding_id, "ProductArn": product_arn}],
        Note={"Text": _truncate_note(note_text), "UpdatedBy": ssm_doc_name},
        Workflow={"Status": workflow_status},
    )


def _build_result(
    *,
    finding_id: str,
    product_arn: str,
    account_id: str,
    resource_region: str,
    bucket_name: str,
    status: Status,
    message: str,
) -> ParseResult:
    return {
        "finding_id": finding_id,
        "product_arn": product_arn,
        "account_id": account_id,
        "resource_region": resource_region,
        "bucket_name": bucket_name,
        "status": status,
        "message": message,
        "object": {
            "Type": "AwsS3Bucket",
            "Id": bucket_name,
            "OutputKey": "Remediation.Output",
        },
    }


def _fail_with_notification(
    *,
    validated: ValidatedFinding,
    message: str,
    ssm_doc_name: str,
) -> ParseResult:
    """Update Security Hub to NOTIFIED and return a FAILED result."""
    try:
        _update_security_hub_finding(
            finding_id=validated.finding_id,
            product_arn=validated.product_arn,
            workflow_status="NOTIFIED",
            note_text=message,
            ssm_doc_name=ssm_doc_name,
        )
    except ClientError as sh_err:
        print(f"[ERROR] {ssm_doc_name}: Failed to update Security Hub: {sh_err}")
        message = (
            message
            + f" WARNING: Security Hub finding was NOT updated due to an API error ({sh_err}). "
            "Please update the finding status manually."
        )
    return _build_result(
        finding_id=validated.finding_id,
        product_arn=validated.product_arn,
        account_id=validated.account_id,
        resource_region=validated.resource_region,
        bucket_name=validated.bucket_name,
        status="FAILED",
        message=message,
    )


def parse_event(event: ParseInput, _context: object) -> ParseResult:
    """SSM entrypoint. Assumes the per-control role, runs the remediation, and
    raises on failure.

    The Orchestrator determines remediation success from the SSM
    AutomationExecutionStatus, not the returned payload. Raising on a FAILED
    result fails the SSM execution so the failure propagates instead of being
    reported as a successful remediation; the success payload is returned only
    when Block Public Access was actually enabled. The Security Hub NOTIFIED
    update for a failure is written by the FAILED path before the raise.
    """
    role_name = event.get("RemediationRoleName", "")
    if not role_name:
        raise ValueError(
            "RemediationRoleName parameter is required for the Macie remediation runbook"
        )
    if not re.match(r"^[a-zA-Z0-9_+=,.@-]{1,64}$", role_name):
        raise ValueError(
            f"RemediationRoleName {role_name!r} is not a valid IAM role name"
        )
    _init_remediation_session(role_name=role_name)

    result = _execute_remediation(event, _context)
    if result["status"] == "FAILED":
        raise RuntimeError(result["message"])
    return result


def _execute_remediation(event: ParseInput, _context: object) -> ParseResult:
    """Parse the OCSF/ASFF finding, enable S3 Block Public Access, update Security Hub.

    Unit tests call this directly (bypassing parse_event), so no per-control
    session is assumed here; _client falls back to module-level boto3 and
    existing @patch mocks keep working.
    """
    try:
        finding = event["Finding"]
        ssm_doc_name = event["SSMDocName"]
    except KeyError as e:
        return _build_result(
            finding_id="",
            product_arn="",
            account_id="",
            resource_region="",
            bucket_name="",
            status="FAILED",
            message=f"Missing required input key: {e}",
        )

    try:
        if _is_asff_finding(finding):
            validated = _validate_asff_finding(finding=finding)
        elif _is_ocsf_finding(finding):
            validated = _validate_finding(finding=finding)
        else:
            raise ValueError("Finding is neither a recognized ASFF nor OCSF shape")
    except ValueError as e:
        print(
            f"[ERROR] {ssm_doc_name}: Finding validation failed, Security Hub not notified: {e}"
        )
        return _build_result(
            finding_id="",
            product_arn="",
            account_id="",
            resource_region="",
            bucket_name="",
            status="FAILED",
            message=f"Invalid finding: {e}",
        )

    try:
        _enable_public_access_block(
            bucket_name=validated.bucket_name, account_id=validated.account_id
        )
    except Exception as e:
        return _fail_with_notification(
            validated=validated,
            message=f"Failed to enable S3 Block Public Access on '{validated.bucket_name}': {e}",
            ssm_doc_name=ssm_doc_name,
        )

    note = (
        f"ASR enabled S3 Block Public Access on bucket '{validated.bucket_name}' "
        "as a first-line protection against sensitive data exposure detected by Macie. "
        "Manual investigation required: review the sensitive data finding, assess the scope "
        "of potential exposure, and resolve this finding when investigation is complete."
    )

    try:
        _update_security_hub_finding(
            finding_id=validated.finding_id,
            product_arn=validated.product_arn,
            workflow_status="NOTIFIED",
            note_text=note,
            ssm_doc_name=ssm_doc_name,
        )
    except ClientError as sh_err:
        print(f"[ERROR] {ssm_doc_name}: Failed to update Security Hub: {sh_err}")
        note = (
            note
            + f" WARNING: Security Hub finding was NOT updated due to an API error ({sh_err}). "
            "Please update the finding status manually."
        )

    return _build_result(
        finding_id=validated.finding_id,
        product_arn=validated.product_arn,
        account_id=validated.account_id,
        resource_region=validated.resource_region,
        bucket_name=validated.bucket_name,
        status="SUCCESS",
        message=note,
    )
