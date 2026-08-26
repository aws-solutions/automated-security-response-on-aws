# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# NOTE: Comments are kept minimal to reduce CloudFormation template size.
# This script is embedded inline in the control runbook SSM document.
import re
import time
from typing import Literal, NamedTuple, Required, TypedDict, TypeGuard

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BOTO_CONFIG = Config(retries={"mode": "standard"})

Status = Literal["SUCCESS", "FAILED"]
Action = Literal["Contain", "Restore"]


def _is_valid_action(value: str) -> TypeGuard[Action]:
    return value in ("Contain", "Restore")


# AWS region tokens are lowercase, partition-prefixed, and end in a digit
# (e.g. us-east-1, eu-west-2, us-gov-west-1, cn-north-1, us-iso-east-1). The
# region comes from untrusted finding data and selects the cross-account
# TargetLocations region for the SSM automation, so it is validated to a
# well-formed region token before use (mirroring the account_id check).
_AWS_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")


# AWS access key IDs are 20 chars: an AKIA (long-term) or ASIA (temporary STS)
# prefix followed by 16 uppercase alphanumerics. Validated because the value
# comes from untrusted finding data and is passed to iam:GetAccessKeyLastUsed.
_ACCESS_KEY_ID_RE = re.compile(r"^(?:AKIA|ASIA)[A-Z0-9]{16}$")


def _validate_region(region: str) -> str:
    if not _AWS_REGION_RE.match(region):
        raise ValueError(f"Invalid region: {region}")
    return region


POLL_INTERVAL_SECONDS = 15
# AWSSupport-ContainIAMPrincipal typically completes in 1-3 minutes.
# Allow up to 10 minutes before timing out.
MAX_POLL_DURATION_SECONDS = 600


class AffectedObject(TypedDict):
    Type: str
    Id: str
    OutputKey: str


class ParseResult(TypedDict):
    finding_id: str
    product_arn: str
    account_id: str
    resource_region: str
    user_name: str
    status: Status
    message: str
    object: AffectedObject
    # On a successful Contain, the exact S3 object key of the backup the managed
    # runbook wrote. Captured so a later Restore can supply it (the managed
    # runbook cannot derive it). Empty for Restore and on failure.
    backup_s3_key: str


# OCSF TypedDicts — only the fields this script reads
class FindingInfo(TypedDict, total=False):
    uid: str


class ProductInfo(TypedDict, total=False):
    uid: str


class Metadata(TypedDict, total=False):
    product: ProductInfo


class AccountInfo(TypedDict, total=False):
    uid: str


class OcsfOwner(TypedDict, total=False):
    account: AccountInfo


class OcsfUser(TypedDict, total=False):
    name: str


class OcsfResource(TypedDict, total=False):
    uid: str
    type: str
    cloud_partition: str
    region: str
    # Real Security Hub V2 OCSF nests the owning account under
    # ``owner.account.uid`` and the IAM user/role name under ``user.name``.
    # OCSF payloads with a user ARN in ``resources[0].uid`` instead carry
    # the account on the resource directly via ``account.uid`` — both
    # shapes are tolerated by ``_validate_finding`` below.
    owner: OcsfOwner
    user: OcsfUser
    account: AccountInfo


class OcsfCloud(TypedDict, total=False):
    account: AccountInfo


class OcsfFinding(TypedDict, total=False):
    finding_info: FindingInfo
    metadata: Metadata
    resources: list[OcsfResource]
    cloud: OcsfCloud


# ASFF TypedDicts — only the fields this script reads
class AsffIamAccessKeyDetails(TypedDict, total=False):
    PrincipalName: str


class AsffResourceDetails(TypedDict, total=False):
    AwsIamAccessKey: AsffIamAccessKeyDetails


class AsffResource(TypedDict, total=False):
    Id: str
    Type: str
    Region: str
    Details: AsffResourceDetails


class AsffFinding(TypedDict, total=False):
    Id: Required[str]
    AwsAccountId: Required[str]
    Resources: Required[list[AsffResource]]
    ProductArn: str
    Region: str


# A finding reaches the runbook either as OCSF (native ingestion) or ASFF (API
# replay of the persisted representation).
InputFinding = OcsfFinding | AsffFinding


class ParseInput(TypedDict, total=False):
    Finding: Required[InputFinding]
    RemediationConfigBucket: Required[str]
    SSMDocName: Required[str]
    RemediationRoleName: Required[str]
    Action: str  # Optional — defaults to "Contain" if not provided
    # Required only for Restore: the exact S3 object key of the backup written
    # by the original Contain execution
    # ({year}/{month}/{day}/{hour}/{minute}/{executionId}.json). The
    # AWS-managed runbook cannot derive it, so it must be supplied by the
    # caller (recorded from the Contain execution output).
    BackupS3KeyName: str


def _is_asff_finding(finding: InputFinding) -> TypeGuard[AsffFinding]:
    """Detect ASFF shape. ASFF carries `Id`/`AwsAccountId`/`Resources`;
    OCSF carries `finding_info`/`resources`/`metadata`."""
    return "Id" in finding and "AwsAccountId" in finding and "Resources" in finding


def _is_ocsf_finding(finding: InputFinding) -> TypeGuard[OcsfFinding]:
    """Detect OCSF shape. Used as a positive guard so the OCSF dispatch narrows
    without relying on negative TypeGuard narrowing (unavailable before py3.13)."""
    return "finding_info" in finding or "resources" in finding


def _validate_asff_finding(*, finding: AsffFinding) -> "ValidatedFinding":
    """Validate ASFF finding and extract key fields.

    Two ASFF shapes reach the runbook:

    1. ``Resources[0]`` carries ``Type = "AwsIamAccessKey"`` (the
       documented ASFF resource type) and ``Id`` is the IAM user ARN
       (``arn:{partition}:iam::{account}:user/{name}``). The user name is
       extracted from the ARN.

    2. V2 ASFF auto-imported by Security Hub for GuardDuty IAMUser findings:
       ``Resources[0]`` carries the CFN-style ``Type =
       "AWS::IAM::AccessKey"`` and ``Id`` is the bare access key id (``AKIA*``
       / ``ASIA*``); the user name is not in the finding payload. Resolve it
       via ``iam:GetAccessKeyLastUsed`` — the script's runtime role
       (``RemediationRoleName``) carries that permission scoped to
       ``user/*``.

    Keep field-extraction logic in sync with ``_validate_finding`` for OCSF.
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

    # Derive partition from the ARN; resource ARNs always carry it as the
    # second element. Default to "aws" so commercial-region findings still
    # flow through if the ARN happens to be malformed.
    partition = "aws"
    if resource_id.startswith("arn:"):
        parts = resource_id.split(":", 3)
        if len(parts) >= 2 and parts[1]:
            partition = parts[1]

    if not re.match(r"^\d{12}$", account_id):
        raise ValueError(f"Invalid account ID: {account_id}")

    resource_region = _validate_region(resource_region)

    user_name = _resolve_asff_user_name(resource=resource)
    return ValidatedFinding(
        finding_id, product_arn, account_id, resource_region, partition, user_name
    )


class ValidatedFinding(NamedTuple):
    finding_id: str
    product_arn: str
    account_id: str
    resource_region: str
    partition: str
    user_name: str


_IAM_ACCESS_KEY_TYPE_PREFIX = "AWS::IAM::AccessKey:"


def _strip_iam_access_key_prefix(resource_id: str) -> str:
    """Strip a leading CFN resource-type prefix from an access key id.

    Some normalized GuardDuty findings carry the access key id prefixed with
    its CFN resource type (e.g. "AWS::IAM::AccessKey:AKIA..."). Return the bare
    id so iam:GetAccessKeyLastUsed accepts it.
    """
    if resource_id.startswith(_IAM_ACCESS_KEY_TYPE_PREFIX):
        return resource_id[len(_IAM_ACCESS_KEY_TYPE_PREFIX) :]
    return resource_id


def _asff_principal_name(*, resource: AsffResource) -> str:
    """Read the IAM principal name Security Hub records under
    ``Details.AwsIamAccessKey.PrincipalName``, or "" when absent."""
    return (
        resource.get("Details", {}).get("AwsIamAccessKey", {}).get("PrincipalName", "")
    )


def _resolve_asff_user_name(*, resource: AsffResource) -> str:
    """Resolve the IAM user name from an ASFF access key resource.

    iam:GetAccessKeyLastUsed is the authoritative primary source for the
    owning user: a user ARN in the resource id is parsed directly; an access
    key id (``Type = "AWS::IAM::AccessKey"`` or an ``AKIA``/``ASIA`` id,
    optionally prefixed with the CFN type) is resolved via the API.

    ``Details.AwsIamAccessKey.PrincipalName`` (when present) is used only as a
    fallback for the access-key path: it lets resolution succeed when the API
    cannot — e.g. the key was already deleted or rotated, so
    iam:GetAccessKeyLastUsed raises NoSuchEntity. When the API fails and no
    PrincipalName is recorded, the API error is re-raised.
    """
    resource_id = resource.get("Id", "")
    if ":user/" in resource_id:
        return _extract_user_name(resource_uid=resource_id)
    candidate = _strip_iam_access_key_prefix(resource_id)
    if resource.get("Type", "") == "AWS::IAM::AccessKey" or re.match(
        r"^(AKIA|ASIA)[0-9A-Z]{8,}$", candidate
    ):
        try:
            return _lookup_user_name_from_access_key(access_key_id=candidate)
        except ValueError:
            principal_name = _asff_principal_name(resource=resource)
            if principal_name:
                return principal_name
            raise
    principal_name = _asff_principal_name(resource=resource)
    if principal_name:
        return principal_name
    raise ValueError(
        "Could not resolve IAM user name from ASFF access key resource: no "
        f"user ARN and no access key id in resource Id {resource_id!r}"
    )


def _extract_user_name(*, resource_uid: str) -> str:
    """Extract IAM user name from OCSF resource UID.

    GuardDuty access key findings use the IAM user ARN as the resource UID:
    arn:aws:iam::{account}:user/{username}
    """
    match = re.search(r":user/(.+)$", resource_uid)
    if not match:
        raise ValueError(
            f"Cannot extract IAM user name from resource UID: {resource_uid}"
        )
    return match.group(1)


def _lookup_user_name_from_access_key(*, access_key_id: str) -> str:
    """Resolve the IAM user that owns an access key via iam:GetAccessKeyLastUsed.

    V2 ASFF (the auto-imported Security Hub representation of a GuardDuty
    IAMUser finding) carries only the bare access key id in
    ``Resources[0].Id`` and ``Resources[0].Type = "AWS::IAM::AccessKey"`` —
    the owning user name is not in the payload. ``iam:GetAccessKeyLastUsed``
    is the documented one-call lookup; the GuardDuty.IAMUser remediation
    role (the script's runtime role) carries that permission scoped to
    ``user/*``.
    """
    if not _ACCESS_KEY_ID_RE.match(access_key_id):
        raise ValueError(f"Invalid access key ID: {access_key_id}")
    iam = boto3.client("iam", config=BOTO_CONFIG)
    try:
        response = iam.get_access_key_last_used(
            AccessKeyId=_strip_iam_access_key_prefix(access_key_id)
        )
    except ClientError as e:
        raise ValueError(
            f"Could not resolve IAM user for access key {access_key_id}: {e}"
        ) from e
    user_name = response.get("UserName", "")
    if not user_name:
        raise ValueError(
            f"iam:GetAccessKeyLastUsed returned no UserName for access key {access_key_id}"
        )
    return str(user_name)


def _resolve_ocsf_account_id(*, finding: OcsfFinding, resource: OcsfResource) -> str:
    """Resolve the 12-digit account id from a V2/V1 OCSF finding.

    Reads the documented V2 locations first (``cloud.account.uid``,
    ``resources[0].owner.account.uid``) and falls back to
    ``resources[0].account.uid`` for callers that put the account id
    directly on the resource. Returns "" when none of the documented
    locations carry it; the caller is responsible for the format check.
    """
    return (
        finding.get("cloud", {}).get("account", {}).get("uid", "")
        or resource.get("owner", {}).get("account", {}).get("uid", "")
        # Fallback for callers that put the account id directly on the
        # resource.
        or resource.get("account", {}).get("uid", "")
    )


def _resolve_ocsf_user_name(*, resource: OcsfResource) -> str:
    """Resolve the IAM user name from an OCSF resource.

    V2 OCSF puts the user name under ``resources[0].user.name``. When that
    field is missing or empty, the resource type tells us how to recover:

    - ``AWS::IAM::AccessKey`` (V2 OCSF auto-import) — ``resources[0].uid``
      is a bare access key id; resolve via ``iam:GetAccessKeyLastUsed``,
      mirroring the V2 ASFF path. Without this branch, the ARN-extraction
      fallback would raise a confusing ValueError citing a malformed ARN
      when the input is in fact a valid access key id.
    - Anything else (``resources[0].uid`` is expected to be a user ARN) —
      extract by regex.
    """
    user_name = resource.get("user", {}).get("name", "")
    if user_name:
        return user_name

    resource_uid = resource.get("uid", "")
    resource_type = resource.get("type", "")
    if resource_type == "AWS::IAM::AccessKey":
        return _lookup_user_name_from_access_key(access_key_id=resource_uid)
    return _extract_user_name(resource_uid=resource_uid)


def _validate_finding(*, finding: OcsfFinding) -> ValidatedFinding:
    """Validate OCSF finding and extract key fields.

    Real Security Hub V2 OCSF Detection findings for GuardDuty IAMUser
    arrive with this shape::

        cloud.account.uid              = "{12-digit account id}"
        resources[0].type              = "AWS::IAM::AccessKey" (CFN-style)
        resources[0].uid               = "{access-key-id}"  (NOT a user ARN)
        resources[0].owner.account.uid = "{12-digit account id}"
        resources[0].user.name         = "{IAM user name}"

    Earlier code read ``resources[0].account.uid`` and extracted the user
    name by regex on ``resources[0].uid`` expecting a user ARN. Both fail
    on the actual customer-flow OCSF: account is not on the resource
    directly, and the resource uid is the bare access key id.

    Read the documented Security Hub V2 locations first; fall back to the
    field placement used by callers that embed a user ARN in
    ``resources[0].uid`` so those keep working.
    """
    finding_info = finding.get("finding_info", {})
    finding_id = finding_info.get("uid", "")
    metadata = finding.get("metadata", {})
    product = metadata.get("product", {})
    product_arn = product.get("uid", "")

    resources = finding.get("resources", [])
    if not resources:
        raise ValueError("No resources found in OCSF finding")

    resource = resources[0]
    resource_region = resource.get("region", "")
    # OCSF cloud_partition is more reliable than ARN regex for GovCloud
    # (aws-us-gov) and China (aws-cn) partitions.
    partition = resource.get("cloud_partition", "aws")

    # Account id: prefer the documented V2 OCSF locations, fall back to
    # ``resources[0].account.uid``. See _resolve_ocsf_account_id.
    account_id = _resolve_ocsf_account_id(finding=finding, resource=resource)

    if not re.match(r"^\d{12}$", account_id):
        raise ValueError(f"Invalid account ID: {account_id}")

    resource_region = _validate_region(resource_region)

    # User name: prefer the documented V2 OCSF location, fall back by
    # resource type. See _resolve_ocsf_user_name.
    user_name = _resolve_ocsf_user_name(resource=resource)

    return ValidatedFinding(
        finding_id, product_arn, account_id, resource_region, partition, user_name
    )


def _invoke_contain_iam_principal(
    *,
    user_name: str,
    action: Action,
    bucket_name: str,
    remediation_role_name: str,
    partition: str,
    account_id: str,
    region: str,
    backup_s3_key: str,
) -> str:
    """Invoke AWSSupport-ContainIAMPrincipal and return execution ID.

    The remediation role (deployed by the member-roles stack as
    ``{solutionId}-GuardDuty.IAMUser-{namespace}``) is used both as the
    cross-account/region ExecutionRoleName for AWSSupport-ContainIAMPrincipal
    and as the AutomationAssumeRole the inner runbook assumes for IAM and S3
    operations.
    """
    ssm = boto3.client("ssm", config=BOTO_CONFIG)
    automation_assume_role = (
        f"arn:{partition}:iam::{account_id}:role/{remediation_role_name}"
    )
    parameters: dict[str, list[str]] = {
        "PrincipalType": ["IAM user"],
        "PrincipalName": [user_name],
        "Action": [action],
        "BackupS3BucketName": [bucket_name],
        "AutomationAssumeRole": [automation_assume_role],
        "DryRun": ["false"],
    }
    # BackupS3KeyName is the exact object key of the backup written by the
    # original Contain run; the runbook validates it is only supplied for
    # Restore and rejects it for Contain.
    #
    # ActivateDisabledKeys=true makes Restore re-enable the access keys that
    # Contain disabled, so a rollback fully reverses the containment (keys
    # active, console access restored, deny policy removed). Without it the
    # managed runbook leaves disabled keys disabled.
    if action == "Restore":
        parameters["BackupS3KeyName"] = [backup_s3_key]
        parameters["ActivateDisabledKeys"] = ["true"]
    response = ssm.start_automation_execution(
        DocumentName="AWSSupport-ContainIAMPrincipal",
        Parameters=parameters,
        TargetLocations=[
            {
                "Accounts": [account_id],
                "Regions": [region],
                "ExecutionRoleName": remediation_role_name,
            }
        ],
    )
    return str(response["AutomationExecutionId"])


def _poll_automation_execution(*, execution_id: str) -> tuple[str, str]:
    """Poll GetAutomationExecution until terminal state.

    Returns (status, failure_message).
    Raises RuntimeError if polling exceeds MAX_POLL_DURATION_SECONDS.
    """
    ssm = boto3.client("ssm", config=BOTO_CONFIG)
    terminal_states = {"Success", "Failed", "TimedOut", "Cancelled"}
    start_time = time.monotonic()

    while True:
        elapsed = time.monotonic() - start_time
        if elapsed > MAX_POLL_DURATION_SECONDS:
            raise RuntimeError(
                f"Polling timed out after {int(elapsed)}s for execution {execution_id}"
            )
        response = ssm.get_automation_execution(AutomationExecutionId=execution_id)
        execution = response.get("AutomationExecution", {})
        status = execution.get("AutomationExecutionStatus", "")
        if status in terminal_states:
            failure_message = execution.get("FailureMessage", "")
            return status, failure_message
        time.sleep(POLL_INTERVAL_SECONDS)


# The managed runbook reports where it stored the backup in its ReportContain
# step output as: "Amazon S3 prefix : {year}/{month}/{day}/{hour}/{minute}/{executionId}.json".
_BACKUP_S3_KEY_RE = re.compile(r"Amazon S3 prefix\s*:\s*(\S+\.json)")


class StepExecution(TypedDict, total=False):
    StepName: str
    Outputs: dict[str, list[str]]


def _resolve_contain_step_executions(*, execution_id: str) -> list[StepExecution]:
    """Return the ContainIAMPrincipal step executions that hold ReportContain.

    The runbook is invoked with TargetLocations, so the execution this script
    started is a fan-out parent whose only step ("{account}_{region}") records
    the real child execution id in its ExecutionId output. The ReportContain
    step (with the backup S3 prefix) lives in that child. Fall back to the
    given execution's own steps when it is not a TargetLocations parent.
    """
    ssm = boto3.client("ssm", config=BOTO_CONFIG)
    steps: list[StepExecution] = ssm.describe_automation_step_executions(
        AutomationExecutionId=execution_id
    ).get("StepExecutions", [])

    child_execution_ids = [
        child_id
        for step in steps
        for child_id in step.get("Outputs", {}).get("ExecutionId", [])
    ]
    if not child_execution_ids:
        return steps

    resolved: list[StepExecution] = []
    for child_id in child_execution_ids:
        resolved.extend(
            ssm.describe_automation_step_executions(AutomationExecutionId=child_id).get(
                "StepExecutions", []
            )
        )
    return resolved


def _get_contain_backup_s3_key(*, execution_id: str, ssm_doc_name: str) -> str:
    """Return the S3 backup key from a successful Contain, or "" if unavailable.

    AWSSupport-ContainIAMPrincipal records the key in its ReportContain step
    output; a later Restore must pass it back (the runbook cannot derive it).
    Containment has already succeeded when this is called, so any failure here
    is swallowed and returns "". The only effect is that rollback becomes
    unavailable for the finding, it never fails the containment.
    """
    try:
        steps = _resolve_contain_step_executions(execution_id=execution_id)
        for step in steps:
            if step.get("StepName") != "ReportContain":
                continue
            for message in step.get("Outputs", {}).get("Message", []):
                match = _BACKUP_S3_KEY_RE.search(message)
                if match:
                    return match.group(1)
    except Exception as backup_key_err:  # noqa: BLE001 - must never fail Contain
        print(
            f"[WARN] {ssm_doc_name}: could not capture backup S3 key for "
            f"execution {execution_id}: {backup_key_err}"
        )
    return ""


# Security Hub BatchUpdateFindings.Note.Text rejects payloads over 512 chars.
# Truncate before posting; the full message is still captured in the SSM doc
# Output and CloudWatch logs.
SECURITY_HUB_NOTE_MAX_LEN = 512


def _truncate_note(text: str) -> str:
    if len(text) <= SECURITY_HUB_NOTE_MAX_LEN:
        return text
    suffix = "..."
    return text[: SECURITY_HUB_NOTE_MAX_LEN - len(suffix)] + suffix


def _update_security_hub_finding(
    *,
    finding_id: str,
    product_arn: str,
    workflow_status: str,
    note_text: str,
    ssm_doc_name: str,
) -> None:
    """Update Security Hub finding workflow status and note."""
    security_hub = boto3.client("securityhub", config=BOTO_CONFIG)
    security_hub.batch_update_findings(
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
    user_name: str,
    status: Status,
    message: str,
    backup_s3_key: str = "",
) -> ParseResult:
    return {
        "finding_id": finding_id,
        "product_arn": product_arn,
        "account_id": account_id,
        "resource_region": resource_region,
        "user_name": user_name,
        "status": status,
        "message": message,
        "backup_s3_key": backup_s3_key,
        "object": {
            "Type": "AwsIamAccessKey",
            "Id": user_name,
            "OutputKey": "Remediation.Output",
        },
    }


def parse_event(event: ParseInput, _context: object) -> ParseResult:
    """SSM entrypoint. Runs the Contain/Restore logic and raises on failure.

    The Orchestrator (check_ssm_execution) determines remediation success from
    the SSM AutomationExecutionStatus, not the returned payload. Raising on a
    FAILED result fails the SSM execution so the failure propagates; the
    success payload is returned only when the action succeeds. The Security Hub
    NOTIFIED update for a failure is written by the FAILED path before the raise.
    """
    result = _execute_contain_or_restore(event, _context)
    if result["status"] == "FAILED":
        raise RuntimeError(result["message"])
    return result


def _execute_contain_or_restore(event: ParseInput, _context: object) -> ParseResult:
    """Parse the OCSF/ASFF finding and invoke AWSSupport-ContainIAMPrincipal for
    the requested Contain or Restore action; returns the ParseResult."""
    finding = event["Finding"]
    action = event.get("Action", "Contain")
    bucket_name = event["RemediationConfigBucket"]
    ssm_doc_name = event["SSMDocName"]
    remediation_role_name = event["RemediationRoleName"]
    backup_s3_key = event.get("BackupS3KeyName", "")

    if not _is_valid_action(action):
        return _build_result(
            finding_id="",
            product_arn="",
            account_id="",
            resource_region="",
            user_name="",
            status="FAILED",
            message=f"Invalid Action: {action!r}. Must be 'Contain' or 'Restore'.",
        )
    validated_action = action  # type checker now knows it's Action

    if validated_action == "Restore" and not backup_s3_key.strip():
        return _build_result(
            finding_id="",
            product_arn="",
            account_id="",
            resource_region="",
            user_name="",
            status="FAILED",
            message=(
                "BackupS3KeyName is required for the Restore action. It must be "
                "the S3 object key of the backup created by the original Contain "
                "execution; AWSSupport-ContainIAMPrincipal cannot derive it."
            ),
        )

    if not bucket_name.strip():
        return _build_result(
            finding_id="",
            product_arn="",
            account_id="",
            resource_region="",
            user_name="",
            status="FAILED",
            message=(
                "RemediationConfigBucket is required but was empty. "
                "AWSSupport-ContainIAMPrincipal requires an S3 bucket for IAM configuration backup/restore."
            ),
        )

    try:
        # Findings ingested via OCSF carry the OCSF shape; findings replayed by
        # the API after persistence are ASFF (the table only stores ASFF). Both
        # paths need to work for end-to-end remediation.
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
            user_name="",
            status="FAILED",
            message=f"Invalid finding: {e}",
        )

    return _invoke_and_poll(
        validated=validated,
        action=validated_action,
        bucket_name=bucket_name,
        remediation_role_name=remediation_role_name,
        ssm_doc_name=ssm_doc_name,
        backup_s3_key=backup_s3_key,
    )


def _fail_with_notification(
    *,
    validated: ValidatedFinding,
    message: str,
    ssm_doc_name: str,
) -> ParseResult:
    """Update Security Hub to NOTIFIED and return a FAILED result.

    If the Security Hub update itself fails, appends a warning to the message
    so the SSM execution output reflects the incomplete notification state.
    """
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
        user_name=validated.user_name,
        status="FAILED",
        message=message,
    )


def _invoke_and_poll(
    *,
    validated: ValidatedFinding,
    action: Action,
    bucket_name: str,
    remediation_role_name: str,
    ssm_doc_name: str,
    backup_s3_key: str,
) -> ParseResult:
    """Invoke AWSSupport-ContainIAMPrincipal, poll to completion, update Security Hub."""
    try:
        execution_id = _invoke_contain_iam_principal(
            user_name=validated.user_name,
            action=action,
            bucket_name=bucket_name,
            remediation_role_name=remediation_role_name,
            partition=validated.partition,
            account_id=validated.account_id,
            region=validated.resource_region,
            backup_s3_key=backup_s3_key,
        )
    except (ValueError, ClientError) as e:
        return _fail_with_notification(
            validated=validated,
            message=f"Failed to invoke AWSSupport-ContainIAMPrincipal for {validated.user_name}: {e}",
            ssm_doc_name=ssm_doc_name,
        )

    # Poll until AWSSupport-ContainIAMPrincipal reaches a terminal state so
    # the Orchestrator and UI reflect the actual outcome of the containment.
    try:
        execution_status, failure_message = _poll_automation_execution(
            execution_id=execution_id
        )
    except (RuntimeError, ClientError) as e:
        return _fail_with_notification(
            validated=validated,
            message=f"Polling failed for execution {execution_id}: {e}",
            ssm_doc_name=ssm_doc_name,
        )

    if execution_status != "Success":
        return _fail_with_notification(
            validated=validated,
            message=(
                f"AWSSupport-ContainIAMPrincipal execution {execution_id} "
                f"failed with status {execution_status}. {failure_message}"
            ),
            ssm_doc_name=ssm_doc_name,
        )

    # GuardDuty containment is a first line of defense — set NOTIFIED, not
    # RESOLVED, because manual investigation is required. Security Hub V1
    # ASFF Workflow.Status only accepts NEW | NOTIFIED | RESOLVED |
    # SUPPRESSED — IN_PROGRESS would be rejected as InvalidInputException.
    captured_backup_s3_key = (
        _get_contain_backup_s3_key(execution_id=execution_id, ssm_doc_name=ssm_doc_name)
        if action == "Contain"
        else ""
    )
    if action == "Contain":
        note = (
            f"ASR initiated credential containment for IAM user '{validated.user_name}' "
            f"(execution: {execution_id}). "
            "Access keys disabled, console access removed, deny-all policy attached. "
            "Manual investigation required: review CloudTrail logs, assess scope of "
            "unauthorized access, and resolve this finding when investigation is complete."
        )
    else:
        note = (
            f"ASR restored IAM user '{validated.user_name}' from backup "
            f"(execution: {execution_id}). "
            "Access keys re-enabled, console access restored, deny-all policy removed."
        )

    # Both Contain and Restore leave the finding NOTIFIED. For Contain it
    # reflects first-line-of-defense containment pending manual investigation.
    # For Restore it deliberately avoids resetting the finding to NEW: ASR only
    # auto-remediates findings whose Workflow.Status is NEW, and a rolled-back
    # finding is still FAILED in Security Hub, so NEW would let auto-remediation
    # immediately re-contain the principal the operator just restored (rollback
    # <-> auto-remediation thrash). NOTIFIED keeps the finding visible for
    # manual follow-up without re-arming the auto-remediation trigger.
    workflow_status = "NOTIFIED"

    try:
        _update_security_hub_finding(
            finding_id=validated.finding_id,
            product_arn=validated.product_arn,
            workflow_status=workflow_status,
            note_text=note,
            ssm_doc_name=ssm_doc_name,
        )
    except ClientError as sh_err:
        print(f"[ERROR] {ssm_doc_name}: Failed to update Security Hub: {sh_err}")
        # Containment succeeded but Security Hub was not updated — append a warning
        # so the SSM execution output reflects the incomplete state. The operator
        # must manually update the finding status in Security Hub.
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
        user_name=validated.user_name,
        status="SUCCESS",
        message=note,
        backup_s3_key=captured_backup_s3_key,
    )
