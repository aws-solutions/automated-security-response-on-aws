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

Returns a status used by the Step Function Choice state to branch:
  ACTIVE       → proceed to execute remediation
  NOTFOUND     → no runbook exists for this control
  NOTACTIVE    → runbook exists but is not in Active state
  NOTENABLED   → playbook is disabled in SSM Parameter Store
  ACCESSDENIED → cannot assume the Orchestrator Member Role

Also returns accountid, resourceregion, automationdocid, and remediationrole
which flow through the rest of the state machine.
"""

import re
from typing import Any, Literal, get_args

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
from layer.powertools_logger import get_logger
from layer.sechub_findings import Finding
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


def _get_ssm_client(account, role, region=""):
    """
    Create a client for ssm
    """
    kwargs = {}
    if region:
        kwargs["region_name"] = region

    return BotoSession(account, f"{role}").client("ssm", **kwargs)


def _add_doc_state_to_answer(doc: str, account: str, region: str, answer: Any) -> None:
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

        docstate = docinfo.get("Status", "unknown")
        if docstate != "Active":
            answer.update(
                {
                    "status": "NOTACTIVE",
                    "message": 'Document Status is not "Active": ' + str(docstate),
                }
            )
            logger.error(answer.message)

        answer.update({"status": "ACTIVE"})

    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        if exception_type in "InvalidDocument":
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


@tracer.capture_lambda_handler  # type: ignore[untyped-decorator]
def lambda_handler(event: dict[str, Any], _: Any) -> utils.StepFunctionLambdaAnswerDict:
    answer: utils.StepFunctionLambdaAnswer = utils.StepFunctionLambdaAnswer()
    logger.info("Processing SSM doc state check", **event)
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
    # Is there alt workflow configuration?
    alt_workflow_doc = event.get("Workflow", {}).get("WorkflowDocument", None)

    automation_docid = f"ASR-{finding.standard_shortname}_{finding.standard_version}_{finding.remediation_control}"
    remediation_role = f"SO0111-Remediate-{finding.standard_shortname}-{finding.standard_version}-{finding.remediation_control}"

    answer.update(
        {"automationdocid": automation_docid, "remediationrole": remediation_role}
    )

    # If alt workflow is configured we don't need to check doc state, as we checked
    # it in get_approval_requirement
    if alt_workflow_doc:
        answer.update({"status": "ACTIVE"})
    else:
        _add_doc_state_to_answer(
            automation_docid, finding.account_id, finding.resource_region, answer
        )

    return answer.json()
