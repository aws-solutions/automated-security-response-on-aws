# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import re
from typing import Any

from botocore.exceptions import ClientError
from layer import utils
from layer.awsapi_cached_client import BotoSession
from layer.powertools_logger import get_logger
from layer.tracer_utils import init_tracer
from layer.utils import StepFunctionLambdaAnswerDict

AWS_PARTITION = os.getenv("AWS_PARTITION")
AWS_REGION = os.getenv("AWS_REGION")
SOLUTION_ID = os.getenv("SOLUTION_ID", "SO0111")
SOLUTION_ID = re.sub(r"^DEV-", "", SOLUTION_ID)

logger = get_logger("exec_ssm_doc")
tracer = init_tracer()

# Document parameters that only a v5 rollback sends (see findingExtraction.ts). Their
# presence identifies an execution as a v5 rollback, which the ENABLE_ROLLBACK switch gates.
V5_ROLLBACK_DOC_PARAMETERS: frozenset[str] = frozenset(
    {
        "Rollback",
        "ExecutionId",
        "RemediationConfigBucket",
        "SnapshotVersionId",
    }
)

# The v4 GuardDuty rollback carries no v5 parameter; it is identified solely by
# Action=Restore (findingExtraction.ts), the inverse of the Contain forward action. Gated
# the same way, so ENABLE_ROLLBACK governs both rollback shapes rather than only v5.
GUARD_DUTY_ROLLBACK_ACTION = "Restore"


def _get_ssm_client(account, role, region=""):
    """
    Create a client for ssm
    """
    kwargs = {}
    if region:
        kwargs["region_name"] = region

    return BotoSession(account, f"{role}").client("ssm", **kwargs)


def _get_iam_client(accountid, role):
    """
    Create a client for iam
    """
    return BotoSession(accountid, role).client("iam")


def _validate_doc_parameters(event: dict[str, Any]) -> dict[str, list[str]]:
    """Validate and return extra SSM document parameters from event.docParameters.

    Only allowlisted parameter names are accepted to prevent overriding
    critical SSM parameters like Finding or AutomationAssumeRole.
    Raises ValueError if validation fails.
    """
    ALLOWED_DOC_PARAMETERS: frozenset[str] = frozenset(
        {
            "Action",
            "BackupS3KeyName",  # existing (GuardDuty rollback)
            "Rollback",
            "ExecutionId",  # snapshot-based rollback
            "RemediationConfigBucket",  # snapshot-based rollback (snapshot bucket)
            "SnapshotVersionId",  # snapshot-based rollback (tamper-proof read)
        }
    )
    raw_doc_parameters = event.get("Detail", {}).get("docParameters", {})
    if not isinstance(raw_doc_parameters, dict):
        raise ValueError(
            f"docParameters must be a dict, got {type(raw_doc_parameters).__name__}"
        )
    validated: dict[str, list[str]] = {}
    for param_name, param_value in raw_doc_parameters.items():
        if not isinstance(param_name, str) or not isinstance(param_value, str):
            raise ValueError("docParameters keys and values must be strings")
        if param_name not in ALLOWED_DOC_PARAMETERS:
            raise ValueError(
                f"Unsupported docParameter: {param_name!r}. Allowed: {sorted(ALLOWED_DOC_PARAMETERS)}"
            )
        validated[param_name] = [param_value]
    return validated


def lambda_role_exists(account: str, rolename: str) -> bool:
    iam = _get_iam_client(account, SOLUTION_ID + "-ASR-Orchestrator-Member")
    try:
        iam.get_role(RoleName=rolename)
        return True
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        if exception_type == "NoSuchEntity":
            return False
        exit("An unhandled client error occurred: " + exception_type)
    except Exception as e:
        exit("An unhandled error occurred: " + str(e))


def _validate_rollback_parameters_allowed(ssm_parameters: dict[str, list[str]]) -> None:
    """Refuse a rollback execution when rollback is disabled globally.

    Two rollback shapes exist (see findingExtraction.ts): a v5 rollback, identified by the
    v5-only parameters, and the v4 GuardDuty rollback, identified by Action=Restore. Either
    means this execution is a rollback. Rollback weakens security posture, which is why the
    API already refuses the action outright when ENABLE_ROLLBACK is not "yes"
    (handlers/findings.ts). Enforcing it here too keeps the switch authoritative for a
    request that reached the state machine another way, for both rollback shapes rather than
    v5 alone.

    Blanking the value instead does not work: SSM's AutomationParameterValue has a
    minimum length of 1, so an empty string fails botocore parameter validation before
    the call is sent -- the execution would die on an opaque ParamValidationError
    rather than a stated reason. Removing the key is worse still, since the document
    then resolves its {{ssm:...}} default, which is the real bucket.
    """
    is_rollback_enabled = os.environ.get("ENABLE_ROLLBACK", "no") == "yes"
    if is_rollback_enabled:
        return
    rollback_parameters = sorted(V5_ROLLBACK_DOC_PARAMETERS & ssm_parameters.keys())
    if ssm_parameters.get("Action") == [GUARD_DUTY_ROLLBACK_ACTION]:
        rollback_parameters = sorted({*rollback_parameters, "Action"})
    if rollback_parameters:
        raise ValueError(
            "Rollback is disabled (ENABLE_ROLLBACK is not 'yes'), so this execution "
            f"cannot carry rollback parameters: {rollback_parameters}"
        )


@tracer.capture_lambda_handler  # type: ignore[untyped-decorator]
def lambda_handler(event: dict[str, Any], _: Any) -> StepFunctionLambdaAnswerDict:
    # Expected:
    # {
    #   Finding: {
    #       AwsAccountId: <aws account>,
    #       ControlId: string
    #   },
    #   RemediationRole: string,
    #   AutomationDocId: string.
    #   SSMExecution: json data
    # }
    # Returns:
    # {
    #   status: { 'UNKNOWN'| string },
    #   message: { '' | string },
    #   executionid: { '' | string }
    # }
    answer = utils.StepFunctionLambdaAnswer()
    automation_document = event.get("AutomationDocument", {})
    logger.info(
        "Processing SSM execution request",
        finding_id=event.get("Finding", {}).get("Id"),
        control_id=automation_document.get("ControlId"),
        account_id=automation_document.get("AccountId"),
        region=automation_document.get("ResourceRegion"),
        event_type=event.get("EventType"),
    )
    if "Finding" not in event or "EventType" not in event:
        answer.update(
            {"status": "ERROR", "message": "Missing required data in request"}
        )
        logger.error(answer.message)
        return answer.json()

    automation_doc = event["AutomationDocument"]
    alt_workflow_doc = event.get("Workflow", {}).get("WorkflowDocument", None)
    alt_workflow_account = event.get("Workflow", {}).get("WorkflowAccount", None)
    alt_workflow_role = event.get("Workflow", {}).get("WorkflowRole", None)

    remote_workflow_doc = (
        alt_workflow_doc
        if alt_workflow_doc
        else event["AutomationDocument"]["AutomationDocId"]
    )

    execution_account = (
        alt_workflow_account if alt_workflow_account else automation_doc["AccountId"]
    )
    execution_region = (
        AWS_REGION if alt_workflow_account else automation_doc.get("ResourceRegion", "")
    )

    if (
        "SecurityStandard" not in automation_doc
        or "ControlId" not in automation_doc
        or "AccountId" not in automation_doc
    ):
        answer.update(
            {
                "status": "ERROR",
                "message": "Missing AutomationDocument data in request: "
                + json.dumps(automation_doc),
            }
        )
        logger.error(answer.message)
        return answer.json()

    # Two different roles are at play here and conflating them breaks every
    # per-control remediation role:
    #
    # * session_role — assumed by THIS lambda (running as Orchestrator-Admin) to
    #   call StartAutomationExecution. Admin may only assume Orchestrator-Member
    #   and Inspector-Automation; those are the sole ARNs in its policy, and the
    #   `-Remediate-*` entry alongside them is commented out in
    #   administrator-stack.ts. Anything else is AccessDenied.
    # * remediation_role — passed as AutomationAssumeRole, so SSM (not this
    #   lambda) assumes it. A per-control role trusts ssm.amazonaws.com and the
    #   Orchestrator-Member role, which is exactly what that requires.
    #
    # Previously the derived per-control role became the session role too, so
    # every custom runbook execution failed with AccessDenied on sts:AssumeRole
    # before SSM was ever called. The alt-workflow role keeps assuming directly:
    # Inspector-Automation is in Admin's allow list and trusts it.
    remediation_role = SOLUTION_ID + "-ASR-Orchestrator-Member"  # default
    session_role = remediation_role
    if alt_workflow_doc and alt_workflow_role:
        remediation_role = alt_workflow_role
        session_role = alt_workflow_role
    elif lambda_role_exists(execution_account, automation_doc["RemediationRole"]):
        remediation_role = automation_doc["RemediationRole"]

    print(
        f"Using role {session_role} to start {remote_workflow_doc} in {execution_account}  {execution_region}, "
        f"running it as {remediation_role}"
    )

    remediation_role_arn = (
        f"arn:{AWS_PARTITION}:iam::{execution_account}:role/{remediation_role}"
    )
    print(f"ARN: {remediation_role_arn}")

    ssm = _get_ssm_client(execution_account, session_role, execution_region)

    ssm_parameters = {
        "Finding": [json.dumps(event["Finding"])],
        "AutomationAssumeRole": [remediation_role_arn],
    }

    # Merge any extra document parameters passed via Detail.docParameters
    # (e.g. Action=Restore for GuardDuty rollback triggered from the API).
    try:
        ssm_parameters.update(_validate_doc_parameters(event))
        _validate_rollback_parameters_allowed(ssm_parameters)
    except ValueError as e:
        answer.update({"status": "ERROR", "message": str(e)})
        logger.error(answer.message)
        return answer.json()

    if remote_workflow_doc != automation_doc["AutomationDocId"]:
        ssm_parameters["RemediationDoc"] = [automation_doc["AutomationDocId"]]
        ssm_parameters["Workflow"] = [json.dumps(event.get("Workflow", {}))]

    # Check if this a security hub finding, if not then we only send the finding.
    workflow_data = event.get("Workflow", {}).get("WorkflowConfig", {})

    if "security_hub" in workflow_data:
        if workflow_data["security_hub"] == "false":
            # Non-Security-Hub workflow findings use a stripped-down parameter set.
            # docParameters (e.g. Action=Restore for rollback) are not applicable here
            # because rollback is only triggered via the ASR API for Security Hub findings.
            ssm_parameters = {
                "Finding": [json.dumps(event["Finding"])],
                "AutomationAssumeRole": [remediation_role_arn],
            }

    exec_id = ssm.start_automation_execution(
        # Launch SSM Doc via Automation
        DocumentName=remote_workflow_doc,
        Parameters=ssm_parameters,
    )["AutomationExecutionId"]

    answer.update(
        {
            "status": "QUEUED",
            "message": f'{exec_id}: {automation_doc["ControlId"]} remediation was successfully invoked via AWS Systems Manager in account {automation_doc["AccountId"]} {execution_region}',
            "executionid": exec_id,
            "remediation_output": "No output available because remediation has not yet finished executing.",
            "executionregion": execution_region,
            "executionaccount": execution_account,
        }
    )

    logger.info(answer.message)

    return answer.json()
