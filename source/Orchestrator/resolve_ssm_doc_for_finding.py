# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Orchestrator Step Function — "Get Automation Document State" step.

Resolves which SSM Automation document to execute for a given finding and
validates that the document exists and is active in the target member account.

For Config/CSPM findings (Security Hub product): parses the finding via the
Finding class to derive standard, version, and control ID, then constructs
the document name as ASR-{standard}_{version}_{control} (e.g.
ASR-AFSBP_1.0.0_AutoScaling.1).

Custom Runbooks (deployed via the MCP runbook authoring feature) are gap-fillers for
controls the solution does not ship a remediation for — they do NOT take priority over
built-in SSM documents. Resolution order:
  1. Check for the exact built-in SSM document for this standard/version/control
  2. If one exists → use the built-in document; no Custom Runbook lookup happens
  3. Otherwise, and only for a manual trigger (``EventType`` of "Security Hub Findings
     - Custom Action" or "- API Action"), query DynamoDB for a DEPLOYED Custom Runbook
  4. If that Custom Runbook's SSM document is Active in the finding's account → use it
  5. Otherwise → fall back to the built-in document name

Two consequences worth being explicit about: an automatically-triggered finding never
reaches a Custom Runbook, and registering a Custom Runbook for a control that already
has a built-in one has no effect on resolution.

Returns a status used by the Step Function Choice state to branch:
  ACTIVE       → proceed to execute remediation
  NOTFOUND     → no runbook exists for this control
  NOTACTIVE    → runbook exists but is not in Active state
  NOTENABLED   → playbook is disabled in SSM Parameter Store
  ACCESSDENIED → cannot assume the Orchestrator Member Role

Also returns accountid, resourceregion, automationdocid, and remediationrole
which flow through the rest of the state machine.
"""

from __future__ import annotations

import os
import re
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal, NotRequired, TypedDict, cast, get_args

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource, Table
    from mypy_boto3_ssm.client import SSMClient
else:
    SSMClient = object

FindingFormat = Literal["ASFF", "OCSF"]


def validated_finding_format(detail: dict[str, Any]) -> FindingFormat:
    """Extract and validate FindingFormat from the detail envelope.

    Returns a validated FindingFormat Literal. Defaults to ASFF if the field
    is missing or has an unexpected value.
    """
    raw = detail.get("findingFormat", "ASFF")
    if raw in get_args(FindingFormat):
        return raw  # type: ignore[no-any-return]
    logger.warning(f"Unexpected FindingFormat '{raw}', defaulting to ASFF")
    return "ASFF"


import boto3
from botocore.exceptions import ClientError
from layer import utils
from layer.awsapi_cached_client import BotoSession
from layer.cloudwatch_metrics import CloudWatchMetrics
from layer.event_transformers import MANUAL_TRIGGER_EVENT_TYPES
from layer.powertools_logger import get_logger
from layer.sechub_findings import Finding, extract_security_control_id
from layer.tracer_utils import init_tracer

ORCH_ROLE_NAME = "SO0111-ASR-Orchestrator-Member"  # role to use for cross-account

# The Inspector.InstanceVulnerability control runbook uses a native
# aws:waitForAwsResourceProperty waiter that needs ssm:GetCommandInvocation on
# its AutomationAssumeRole. To keep that (unavoidably wildcard) read off the
# shared Orchestrator-Member role, Inspector findings run under a dedicated,
# Inspector-only automation role (created in MemberRolesStack). All other
# multi-service controls continue to use Orchestrator-Member.
INSPECTOR_REMEDIATION_ID = "Inspector.InstanceVulnerability"
INSPECTOR_AUTOMATION_ROLE_NAME = "SO0111-ASR-Inspector-Automation"


logger = get_logger("resolve_ssm_doc_for_finding")
tracer = init_tracer()

session = boto3.session.Session()
AWS_REGION = session.region_name


class CustomRunbookRecord(TypedDict):
    """One CustomRunbookTable record as read back from DynamoDB.

    Every field is `NotRequired`: these records are written by the MCP authoring
    feature and by older versions of it, so a field can be absent (a runbook
    registered before per-account tracking existed has no `deployedAccounts`) or
    malformed. That is what the usability filter, `_as_int`, and the isinstance
    guards below exist for — the type documents the expected shape and catches
    key-name typos, it does not promise the data is well-formed.

    `version` is a `Decimal` in practice (DynamoDB reads an `N` attribute back as
    one) but is declared wider because a malformed record can hold anything.
    """

    runbookId: NotRequired[str]
    version: NotRequired[Decimal | int | str]
    controlId: NotRequired[str]
    status: NotRequired[str]
    ssmDocumentName: NotRequired[str]
    remediationRole: NotRequired[str]
    deployedAt: NotRequired[str]
    createdAt: NotRequired[str]
    # accountId -> {"runbookVersion": ..., "status": ..., ...}
    deployedAccounts: NotRequired[dict[str, Any]]


class CustomRunbookInfo(TypedDict):
    ssmDocumentName: str
    remediationRole: str
    runbookVersion: int
    # Runbook version the finding's own account is recorded as running, or None
    # when that account has no recorded release of this runbook.
    memberRunbookVersion: int | None
    memberStatus: str | None


def _get_dynamodb_resource() -> "DynamoDBServiceResource":
    """Create a DynamoDB resource for querying the Custom Runbook table."""
    return boto3.resource("dynamodb", region_name=AWS_REGION)  # type: ignore[no-any-return]


def _as_int(value: str | int | Decimal | None, default: int = 0) -> int:
    """Coerce a DynamoDB value to int, falling back for malformed data.

    Version fields come from external DynamoDB records. A key attribute typed `N`
    is read back as a Decimal, but a nested field (e.g. a member's `runbookVersion`)
    could be a malformed non-numeric string. int() on that would raise ValueError
    and crash the whole Step Functions execution over one bad record, so an
    unparseable value logs a warning and falls back instead.
    """
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        logger.warning(f"Non-numeric version value {value!r}; using {default}")
        return default


def _query_deployed_custom_runbooks(
    table: "Table", control_id: str
) -> list[CustomRunbookRecord]:
    """Read every DEPLOYED record for this control, following pagination.

    No Limit: deploying a new version does not demote the previous one, so a
    control can have several DEPLOYED records at once. The GSI's sort key is
    `status`, which is identical across them, so `Limit=1` would return an
    arbitrary one — meaning the same finding could be remediated by v1 or v3 from
    one execution to the next. Read every candidate and pick deliberately.

    `LastEvaluatedKey` is followed for the same reason the TypeScript reader does
    it (`CustomRunbookRepository.findByControlId`): a single query returns at most
    1 MB, and the latest deployment can be on any page.
    """
    items: list[CustomRunbookRecord] = []
    start_key: dict[str, Any] | None = None
    while True:
        request: dict[str, Any] = {
            "IndexName": "controlId-status-index",
            "KeyConditionExpression": "controlId = :cid AND #s = :status",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":cid": control_id, ":status": "DEPLOYED"},
        }
        if start_key:
            request["ExclusiveStartKey"] = start_key
        response = table.query(**request)
        # boto3 hands back untyped items; this read is the one place that shape is
        # asserted, so downstream code works with CustomRunbookRecord instead of
        # a bare dict. The record's fields are all NotRequired precisely because
        # this cast cannot verify them.
        items.extend(cast(list[CustomRunbookRecord], response.get("Items", [])))
        start_key = response.get("LastEvaluatedKey")
        if not start_key:
            return items


def _deployment_recency_key(record: CustomRunbookRecord) -> tuple[str, int]:
    """Order DEPLOYED records by when each was last deployed, then by version.

    Recency comes before version because a rollback re-deploys an *older* version: the
    release that is actually live is the one deployed most recently, not the highest
    numbered. Ordering by version first would keep naming the rolled-back version as
    current, which misreports runbookVersion and makes every account correctly holding
    the restored version look like it has drifted.

    Version breaks ties between records deployed at the same instant, and records
    predating the deployedAt attribute fall back to createdAt.
    """
    return (
        str(record.get("deployedAt") or record.get("createdAt", "")),
        _as_int(record.get("version")),
    )


def _select_current_deployed_runbook(
    items: list[CustomRunbookRecord],
) -> CustomRunbookRecord:
    """Select the most recently deployed record, across versions and runbook IDs.

    One control can have several DEPLOYED records: successive versions of one runbook
    (deploy does not demote the version it replaces) and, after a replacement, records
    under a different runbookId. Both cases are decided the same way, by deployment
    recency, with runbookId as a final tiebreak so the choice is deterministic.
    """
    return max(
        items,
        key=lambda candidate: (
            *_deployment_recency_key(candidate),
            str(candidate.get("runbookId", "")),
        ),
    )


def _get_member_release_state(
    item: CustomRunbookRecord, account_id: str
) -> tuple[str | None, int | None]:
    """Report the runbook release the finding's own account is recorded as holding.

    Returns ``(status, version)``, each None when this account has no recorded
    release of the runbook.

    Both the `deployedAccounts` map and the per-account entry inside it come from an
    external DynamoDB record, so each is type-checked on its own: a malformed record
    where either is a list or a string would raise AttributeError on `.get` and crash
    the whole Step Functions execution over one bad record. A non-dict at either level
    is treated as "no recorded release" instead.
    """
    raw_accounts = item.get("deployedAccounts")
    accounts: dict[str, Any] = raw_accounts if isinstance(raw_accounts, dict) else {}
    raw_member_state = accounts.get(account_id)
    member_state: dict[str, Any] = (
        raw_member_state if isinstance(raw_member_state, dict) else {}
    )

    member_status: str | None = member_state.get("status")
    member_version: int | None = (
        _as_int(member_state["runbookVersion"])
        if "runbookVersion" in member_state
        else None
    )
    return member_status, member_version


def _log_member_release_state(
    control_id: str,
    account_id: str,
    member_status: str | None,
    member_version: int | None,
    runbook_version: int,
) -> None:
    """Log if the finding's account has no recorded release, or a version skew."""
    if account_id and member_status is None:
        logger.warning(
            f"Custom Runbook for controlId={control_id} has no recorded release to account {account_id}",
        )
    elif member_version is not None and member_version != runbook_version:
        logger.warning(
            f"Custom Runbook version skew for controlId={control_id} in account {account_id}: "
            f"account runs v{member_version} (status={member_status}), latest deployed is v{runbook_version}",
        )


def _check_custom_runbook(
    control_id: str, *, account_id: str = ""
) -> CustomRunbookInfo | None:
    """Resolve the custom runbook to run for this control, or None if there is none.

    Raises rather than returning None when the lookup itself fails. `None` means
    "no DEPLOYED custom runbook exists", and the caller acts on that by falling
    through to a built-in that may not exist — so a DynamoDB throttle, a missing
    `dynamodb:Query` grant on the GSI, or a malformed record decoded as a failure
    would silently discard a runbook that *is* deployed and leave the finding
    unremediated with no signal. Raising fails the Step Functions execution, which
    is visible and retryable: the "Get Automation Document State" task retries
    `States.TaskFailed` three times with backoff, so a DynamoDB throttle is retried
    rather than mapped to a status the state machine would treat as final.
    """
    table_name = os.environ.get("CUSTOM_RUNBOOK_TABLE_NAME", "")
    if not table_name:
        logger.debug(
            "CUSTOM_RUNBOOK_TABLE_NAME not set, skipping Custom Runbook lookup"
        )
        return None
    # An empty control id cannot be a GSI key, so querying it would manufacture a
    # failure out of a finding we merely cannot classify.
    if not control_id:
        logger.info("No control id on the finding; skipping Custom Runbook lookup")
        return None

    dynamodb = _get_dynamodb_resource()
    table = dynamodb.Table(table_name)

    # The raise is deliberate (see the docstring), but a bare traceback in the
    # execution history does not say which control or table was being read. Log that
    # context, then let the error propagate to the state machine's retry.
    try:
        items = _query_deployed_custom_runbooks(table, control_id)
    except ClientError as error:
        logger.error(
            f"Custom Runbook lookup failed for controlId={control_id} on table {table_name}: "
            f"{error.response['Error']['Code']} — failing the execution rather than "
            f"reporting 'no custom runbook'",
        )
        raise

    if not items:
        logger.info(f"No DEPLOYED Custom Runbook found for controlId={control_id}")
        return None

    # Drop unusable records BEFORE selecting a winner. A runbook needs both a
    # document to run and its own scoped role; without either it cannot be
    # executed. Filtering first means a single malformed latest record does not
    # hide a valid older one — selection runs over the usable candidates only.
    usable_items = [
        candidate
        for candidate in items
        if candidate.get("ssmDocumentName") and candidate.get("remediationRole")
    ]
    dropped = len(items) - len(usable_items)
    if dropped:
        logger.warning(
            f"Ignoring {dropped} DEPLOYED Custom Runbook record(s) for controlId={control_id} "
            f"missing ssmDocumentName or remediationRole",
        )
    if not usable_items:
        logger.warning(
            f"No usable DEPLOYED Custom Runbook for controlId={control_id} "
            f"(all records missing ssmDocumentName or remediationRole)",
        )
        return None

    # Deployment recency decides which record is live, both between versions of one
    # runbook and across replacement runbook IDs — a rollback re-deploys an older
    # version, so the highest version number is not necessarily the active one.
    item = _select_current_deployed_runbook(usable_items)
    if len(usable_items) > 1:
        candidates = sorted(
            (
                str(candidate.get("runbookId", "")),
                _as_int(candidate.get("version")),
                str(candidate.get("deployedAt") or "legacy"),
            )
            for candidate in usable_items
        )
        logger.info(
            f"Multiple DEPLOYED Custom Runbooks for controlId={control_id} "
            f"(candidates={candidates}) — selected runbook {item.get('runbookId', 'unknown')} "
            f"version {_as_int(item.get('version'))}"
        )

    # Guaranteed present by the usable_items filter above; assigned for clarity.
    ssm_doc_name = str(item["ssmDocumentName"])
    remediation_role = str(item["remediationRole"])
    runbook_version = _as_int(item.get("version"))

    # Custom runbooks are deployed copy-per-member, so the account that owns
    # the finding may still be running an earlier version that was never
    # released to it. The document itself is verified separately; this only
    # reports which version that account is recorded as holding, so version
    # skew shows up in the remediation logs instead of being invisible.
    member_status, member_version = _get_member_release_state(item, account_id)
    _log_member_release_state(
        control_id, account_id, member_status, member_version, runbook_version
    )

    logger.info(
        f"Found DEPLOYED Custom Runbook for controlId={control_id}: doc={ssm_doc_name} role={remediation_role}",
    )
    return CustomRunbookInfo(
        ssmDocumentName=ssm_doc_name,
        remediationRole=remediation_role,
        runbookVersion=runbook_version,
        memberRunbookVersion=member_version,
        memberStatus=member_status,
    )


def _get_ssm_client(account: str, role: str, region: str = "") -> "SSMClient":
    """
    Create a client for ssm
    """
    kwargs = {}
    if region:
        kwargs["region_name"] = region

    return BotoSession(account, f"{role}").client("ssm", **kwargs)  # type: ignore[no-any-return]


def _add_doc_state_to_answer(
    doc: str, account: str, region: str, answer: utils.StepFunctionLambdaAnswer
) -> None:
    try:
        # Connect to APIs
        ssm = _get_ssm_client(account, ORCH_ROLE_NAME, region)

        # Validate input
        docinfo = ssm.describe_document(Name=doc)["Document"]

        doctype = docinfo.get("DocumentType", "unknown")

        if doctype != "Automation":
            answer.update(
                {
                    "status": "ERROR",
                    "message": 'Document Type is not "Automation": ' + str(doctype),
                }
            )
            logger.error(answer.message)
            return

        docstate = docinfo.get("Status", "unknown")
        if docstate != "Active":
            answer.update(
                {
                    "status": "NOTACTIVE",
                    "message": 'Document Status is not "Active": ' + str(docstate),
                }
            )
            logger.error(answer.message)
            return

        answer.update({"status": "ACTIVE"})

    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        if exception_type == "InvalidDocument":
            answer.update(
                {"status": "NOTFOUND", "message": f"Document {doc} does not exist."}
            )
            logger.error(answer.message)
        elif exception_type == "AccessDenied":
            answer.update(
                {
                    "status": "ACCESSDENIED",
                    "message": f"Could not assume role for {doc} in {account} in {region}",
                }
            )
            logger.error(answer.message)
            try:
                cloudwatch_metrics = CloudWatchMetrics()
                cloudwatch_metric = {
                    "MetricName": "AssumeRoleFailure",
                    "Unit": "Count",
                    "Value": 1,
                }
                cloudwatch_metrics.send_metric(cloudwatch_metric)
            except Exception:
                logger.debug("Did not send Cloudwatch metric")
        elif exception_type == "ThrottlingException":
            # Re-raise throttling exceptions so Step Functions can retry with backoff
            logger.warning(f"SSM API throttled for document {doc}, will retry")
            raise
        else:
            answer.update(
                {
                    "status": "CLIENTERROR",
                    "message": "An unhandled client error occurred: " + exception_type,
                }
            )
            logger.error(answer.message)

    except Exception as e:
        answer.update(
            {"status": "ERROR", "message": "An unhandled error occurred: " + str(e)}
        )
        logger.error(answer.message)


def _resolve_doc_for_external_product(
    event: dict[str, Any], answer: utils.StepFunctionLambdaAnswer
) -> utils.StepFunctionLambdaAnswerDict:
    """Resolve the SSM automation document for a non-Security Hub product finding.

    External/partner products don't have standard/version/control metadata.
    The runbook name and role are read from the Workflow object, which was
    populated by get_approval_requirement via SSM parameter lookup keyed by
    product name. Returns ACTIVE immediately since doc state was already
    validated upstream in get_approval_requirement.
    """
    workflow_doc = event.get("Workflow", {})
    non_sec_hub_finding = event["Finding"]
    non_sec_hub_resources = non_sec_hub_finding.get("Resources", [])
    resource_region = AWS_REGION
    if len(non_sec_hub_resources) >= 1:
        resource_region = non_sec_hub_resources[0].get("Region", "")
    answer.update(
        {
            "securitystandard": "N/A",
            "securitystandardversion": "N/A",
            "controlid": "N/A",
            "playbookenabled": "N/A",
            "accountid": non_sec_hub_finding["AwsAccountId"],
            "resourceregion": resource_region,
            "automationdocid": workflow_doc["WorkflowDocument"],
            "remediationrole": (
                workflow_doc["WorkflowRole"]
                if workflow_doc["WorkflowRole"] != ""
                else "SO0111-UseDefaultRole"
            ),
        }
    )
    answer.update({"status": "ACTIVE"})
    return answer.json()


def _get_resource_region(finding: dict[str, Any], finding_format: FindingFormat) -> str:
    """Extract resource region from a finding based on its format."""
    if finding_format == "OCSF":
        resources = finding.get("resources", [])
        if resources:
            return str(resources[0].get("region", AWS_REGION))
        return AWS_REGION
    resources = finding.get("Resources", [])
    if resources:
        return str(resources[0].get("Region", AWS_REGION))
    return AWS_REGION


def _get_account_id_from_finding(
    finding: dict[str, Any], finding_format: FindingFormat
) -> str:
    """Extract account ID from a finding based on its format."""
    if finding_format == "OCSF":
        account_uid = str(finding.get("cloud", {}).get("account", {}).get("uid", ""))
        if not account_uid:
            logger.warning("OCSF finding missing cloud.account.uid")
        return account_uid
    account_id = str(finding.get("AwsAccountId", ""))
    if not account_id:
        logger.warning("ASFF finding missing AwsAccountId")
    return account_id


def _resolve_doc_for_multi_service_finding(
    event: dict[str, Any],
    remediation_id: str,
    finding_format: FindingFormat,
    answer: utils.StepFunctionLambdaAnswer,
) -> utils.StepFunctionLambdaAnswerDict:
    """
    Resolve doc for multi-service findings (Inspector, GuardDuty, Macie, IAM Access Analyzer).
    Constructs automation doc ID as ASR-{remediationId} and determines the target account/region.
    """
    finding = event["Finding"]

    if not re.match(r"^[A-Za-z0-9.]+$", remediation_id):
        answer.update(
            {
                "status": "ERROR",
                "message": f"Invalid remediation ID format: {remediation_id}",
            }
        )
        logger.error(answer.message)
        return answer.json()

    automation_docid = f"ASR-{remediation_id}"
    # The outer ASR-{control} document runs as Orchestrator-Member. The
    # permissions it uses (ssm:StartAutomationExecution / GetAutomationExecution,
    # securityhub:BatchUpdateFindings) are the cross-account control-runbook
    # execution permissions Orchestrator-Member already holds — it performs no
    # privileged remediation itself. The actual remediation runs one layer
    # deeper as the per-control role (SO0111-{control}), assumed by the runbook
    # via its RemediationRoleName input; that role's trust policy only trusts
    # Orchestrator-Member, and it is where all IAM/S3/Secrets containment
    # permissions are bounded. Multi-service findings have no per-standard
    # SO0111-Remediate-* role, so this names Orchestrator-Member directly.
    # Inspector.InstanceVulnerability instead runs under a
    # dedicated, Inspector-only automation role so the native patch waiter's
    # ssm:GetCommandInvocation grant stays off the shared Orchestrator-Member
    # role. If that role is not yet deployed in the target account, exec_ssm_doc
    # falls back to Orchestrator-Member (see lambda_role_exists there).
    if remediation_id == INSPECTOR_REMEDIATION_ID:
        multi_service_assume_role = INSPECTOR_AUTOMATION_ROLE_NAME
    else:
        multi_service_assume_role = ORCH_ROLE_NAME

    resource_region = _get_resource_region(finding, finding_format)
    account_id = _get_account_id_from_finding(finding, finding_format)

    if not account_id:
        answer.update(
            {
                "status": "ERROR",
                "message": "Could not determine account ID from finding",
            }
        )
        logger.error(answer.message)
        return answer.json()

    answer.update(
        {
            "securitystandard": "MultiService",
            "securitystandardversion": "4.0.0",
            "controlid": remediation_id,
            "playbookenabled": "True",
            "accountid": account_id,
            "resourceregion": resource_region,
            "automationdocid": automation_docid,
            "remediationrole": multi_service_assume_role,
        }
    )

    # Check if the automation document exists and is active in the target account
    _add_doc_state_to_answer(automation_docid, account_id, resource_region, answer)

    return answer.json()


def _resolve_doc_for_custom_runbook(
    event: dict[str, Any],
    finding: Finding,
    answer: utils.StepFunctionLambdaAnswer,
) -> utils.StepFunctionLambdaAnswerDict:
    """
    Resolve a deployed custom runbook for a Security Hub finding. Called only after
    the built-in document lookup returned NOTFOUND. Leaves the answer as NOTFOUND
    when no custom runbook is deployed for the control in the target account.
    """
    # No built-in exists — try a deployed custom runbook. Custom runbooks are
    # manual-trigger only, so the event-type gate is checked BEFORE the DynamoDB
    # lookup: an automatically-triggered finding must never query the custom-runbook
    # table, so a throttle or access error there cannot fail an automatic execution.
    event_type: str = event["EventType"]
    is_manual_trigger = event_type in MANUAL_TRIGGER_EVENT_TYPES
    if not is_manual_trigger:
        logger.info(
            f"No built-in remediation for controlId={finding.standard_control} and "
            f"custom runbooks only run on manual trigger (EventType={event_type}); reporting NOTFOUND",
        )
        return answer.json()

    # A custom runbook is a gap-filler for controls the solution does not ship, so
    # it is only consulted here, when no built-in was found above.
    #
    # Records are keyed by the canonical security control id (IAM.4), which is what
    # the rest of the product registers under. Before this lookup used the canonical
    # id it queried the standard-specific id (CIS 1.12) directly, so a record
    # registered that way still resolves: when the two differ and the canonical
    # lookup finds nothing, the standard-specific id is tried second and the match is
    # logged so the record can be re-registered under the canonical id.
    custom_runbook_control_id = (
        extract_security_control_id(event) or finding.standard_control
    )
    custom_runbook = _check_custom_runbook(
        custom_runbook_control_id, account_id=finding.account_id
    )
    if (
        custom_runbook is None
        and finding.standard_control
        and finding.standard_control != custom_runbook_control_id
    ):
        custom_runbook = _check_custom_runbook(
            finding.standard_control, account_id=finding.account_id
        )
        if custom_runbook is not None:
            logger.warning(
                f"Custom Runbook {custom_runbook['ssmDocumentName']} is registered under "
                f"standard-specific controlId={finding.standard_control}; re-register it "
                f"under the canonical controlId={custom_runbook_control_id}",
            )
            custom_runbook_control_id = finding.standard_control
    if custom_runbook is not None:
        custom_doc = custom_runbook["ssmDocumentName"]
        custom_role = custom_runbook["remediationRole"]
        # Each member account holds its own copy of the document — nothing is
        # shared out of the admin account — so a plain local document name is
        # the only valid reference, and its presence in this account is what
        # decides whether the runbook was actually released here.
        answer.update(
            {
                "automationdocid": custom_doc,
                "remediationrole": custom_role,
                "message": "",
            }
        )
        _add_doc_state_to_answer(
            custom_doc, finding.account_id, finding.resource_region, answer
        )
        if answer.status == "ACTIVE":
            logger.info(
                f"Using Custom Runbook {custom_doc} (account v{custom_runbook['memberRunbookVersion']}) "
                f"for controlId={custom_runbook_control_id}",
            )
            return answer.json()

        # Custom Runbook SSM document is not usable (NOTACTIVE / ERROR /
        # ACCESSDENIED). _add_doc_state_to_answer has set the status and a message
        # describing that state; leave both — and the custom doc as automationdocid —
        # so the operator sees the real problem (a document stuck Updating, or a role
        # ASR cannot assume) instead of the misleading "ASR ships no remediation for
        # this control" that a built-in NOTFOUND would imply. The message is rewritten
        # to name the custom document explicitly, since some states report only the
        # state and not which document it belongs to.
        answer.update(
            {
                "message": f"Custom Runbook {custom_doc} is not usable (status {answer.status}) "
                f"for controlId={custom_runbook_control_id}.",
            }
        )
        logger.error(answer.message)

    return answer.json()


@tracer.capture_lambda_handler  # type: ignore[untyped-decorator]
def lambda_handler(event: dict[str, Any], _: Any) -> utils.StepFunctionLambdaAnswerDict:
    answer: utils.StepFunctionLambdaAnswer = utils.StepFunctionLambdaAnswer()
    logger.info(
        "Processing SSM doc state check",
        remediation_id=event.get("Detail", {}).get("remediationId"),
        finding_type=event.get("Detail", {}).get("findingType"),
        event_type=event.get("EventType"),
    )
    if "Finding" not in event or "EventType" not in event:
        answer.update(
            {"status": "ERROR", "message": "Missing required data in request"}
        )
        logger.error(answer.message)
        return answer.json()

    # Check for multi-service remediation (GuardDuty, Inspector, Macie via OCSF;
    # IAM Access Analyzer via ASFF)
    detail = event.get("Detail", {})
    remediation_id = detail.get("remediationId", "")
    finding_format = validated_finding_format(detail)
    finding_type = detail.get("findingType", "securityControl")

    if finding_type == "multiService":
        return _resolve_doc_for_multi_service_finding(
            event, remediation_id, finding_format, answer
        )

    product_name = (
        event["Finding"]
        .get("ProductFields", {})
        .get("aws/securityhub/ProductName", "Security Hub")
    )

    if product_name != "Security Hub":
        return _resolve_doc_for_external_product(event, answer)

    finding = Finding(event["Finding"])

    answer.update(
        {
            "securitystandard": (
                finding.standard_shortname
                if finding.standard_shortname != "error"
                else finding.standard_name
            ),
            "securitystandardversion": finding.standard_version,
            "controlid": finding.standard_control,
            "playbookenabled": finding.playbook_enabled,
            "accountid": finding.account_id,
            "resourceregion": finding.resource_region,
            "remediationrole": "",
            "automationdocid": "",
        }
    )

    if finding.playbook_enabled != "True":
        answer.update(
            {
                "status": "NOTENABLED",
                "message": f'Security Standard is not enabled": "{finding.standard_name} version {finding.standard_version}"',
            }
        )
        return answer.json()

    automation_docid = f"ASR-{finding.standard_shortname}_{finding.standard_version}_{finding.remediation_control}"
    remediation_role = f"SO0111-Remediate-{finding.standard_shortname}-{finding.standard_version}-{finding.remediation_control}"

    # An explicitly configured alt workflow (from get_approval_requirement) is an
    # operator override that takes precedence over both the built-in resolution and
    # any custom runbook. Its doc state was already checked in get_approval_requirement.
    alt_workflow_doc = event.get("Workflow", {}).get("WorkflowDocument", None)
    if alt_workflow_doc:
        answer.update(
            {
                "automationdocid": automation_docid,
                "remediationrole": remediation_role,
                "status": "ACTIVE",
            }
        )
        return answer.json()

    # Built-in resolution first. Its describe_document is the single authoritative
    # check of the exact document this finding would execute: an ACTIVE/NOTACTIVE/
    # ERROR/ACCESSDENIED result all mean "the built-in path owns this finding" and
    # are returned as-is (this is what preserves the ACCESSDENIED branch and its
    # AssumeRoleFailure metric on the common path). Only a NOTFOUND — the document
    # genuinely does not exist — opens the custom-runbook path below, so there is
    # exactly one describe_document call for the built-in document.
    answer.update(
        {"automationdocid": automation_docid, "remediationrole": remediation_role}
    )
    _add_doc_state_to_answer(
        automation_docid, finding.account_id, finding.resource_region, answer
    )
    if answer.status != "NOTFOUND":
        return answer.json()

    return _resolve_doc_for_custom_runbook(event, finding, answer)
