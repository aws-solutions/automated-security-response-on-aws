# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Check the value of the Lambda Environmental variable RUN_WORKFLOW. If set,
send the remediation input to the member account runbook named in the
RUN_WORKFLOW variable.

This Lambda can be further modified by the customer to gather additional
information to determine when to inject RUN_WORKFLOW. Methods are defined
and stubbed out to support this: _is_remediation_destructive(), etc.
"""

import json
import os
import re
from typing import Any, Dict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from layer import utils
from layer.awsapi_cached_client import BotoSession
from layer.powertools_logger import get_logger
from layer.sechub_findings import Finding
from layer.simple_validation import extract_safe_product_name, safe_ssm_path
from layer.tracer_utils import init_tracer
from layer.utils import StepFunctionLambdaAnswerDict

logger = get_logger("get_approval_requirement")
tracer = init_tracer()

# If env WORKFLOW_RUNBOOK is set and not blank then all remediations will be
# executed through this runbook, if it is present and enabled in the member
# account.
SOLUTION_ID = os.getenv("SOLUTION_ID", "SO0111")
SOLUTION_ID = re.sub(r"^DEV-", "", SOLUTION_ID)


def _get_ssm_client(account, role, region=""):
    """
    Create a client for ssm
    """
    sess = BotoSession(account, f"{role}")
    kwargs = {}
    if region:
        kwargs["region_name"] = region

    return sess.client("ssm", **kwargs)


def _is_remediation_destructive(_, __, ___):
    return False


def _is_account_sensitive(_):
    return False


def _is_automatic_trigger(event_type):
    if event_type == "Security Hub Findings - Imported":
        return False
    else:
        return True


def _is_custom_action_trigger(event_type):
    if event_type == "Security Hub Findings - Imported":
        return True
    else:
        return False


def get_running_account():
    return boto3.client("sts").get_caller_identity()["Account"]


def _get_alternate_workflow(accountid):
    """
    Get the alt workflow based on environmental variables for this lambda
    and whether the alt runbook is active. Note that alt workflow must run
    in the same region as the Step Function.
    """
    running_account = get_running_account()

    # Is an alternate workflow defined?
    WORKFLOW_RUNBOOK = os.getenv("WORKFLOW_RUNBOOK", "")
    WORKFLOW_RUNBOOK_ACCOUNT = os.getenv("WORKFLOW_RUNBOOK_ACCOUNT", "member")
    WORKFLOW_RUNBOOK_ROLE = os.getenv("WORKFLOW_RUNBOOK_ROLE", "")

    # Disabled by removing the Lambda environmental var or setting to ''
    if not WORKFLOW_RUNBOOK:
        return (None, None, None)

    if WORKFLOW_RUNBOOK_ACCOUNT.lower() == "member":
        WORKFLOW_RUNBOOK_ACCOUNT = accountid
    elif WORKFLOW_RUNBOOK_ACCOUNT.lower() == "admin":
        WORKFLOW_RUNBOOK_ACCOUNT = running_account
    else:
        # log an error - bad config
        logger.error(
            f'WORKFLOW_RUNBOOK_ACCOUNT config error: "{WORKFLOW_RUNBOOK_ACCOUNT}" is not valid. Must be "member" or "admin"'
        )
        return (None, None, None)

    # Make sure it exists and is active
    if _doc_is_active(WORKFLOW_RUNBOOK, WORKFLOW_RUNBOOK_ACCOUNT):
        return (WORKFLOW_RUNBOOK, WORKFLOW_RUNBOOK_ACCOUNT, WORKFLOW_RUNBOOK_ROLE)
    else:
        return (None, None, None)


def _doc_is_active(doc: str, account: str) -> bool:
    try:
        ssm = _get_ssm_client(account, SOLUTION_ID + "-ASR-Orchestrator-Member")
        docinfo = ssm.describe_document(Name=doc)["Document"]

        doctype = docinfo.get("DocumentType", "unknown")
        docstate = docinfo.get("Status", "unknown")

        if doctype == "Automation" and docstate == "Active":
            return True
        else:
            return False

    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        if exception_type in "InvalidDocument":
            return False
        else:
            logger.error("An unhandled client error occurred: " + exception_type)
            return False

    except Exception as e:
        logger.error("An unhandled error occurred: " + str(e))
        return False


def _evaluate_approval_and_alt_workflow(
    answer: utils.StepFunctionLambdaAnswer,
    *,
    event_type: str,
    standard_shortname: str,
    standard_version: str,
    standard_control: str,
    account_id: str,
) -> None:
    """
    Apply the customer-extensible approval/destructive/sensitive evaluation and,
    when an alternate workflow is configured and active, redirect the remediation
    to it. Shared by both the SecurityHub-standard path and the multi-service path
    so the two cannot diverge: a customer who extends the destructive/sensitive
    stubs or configures WORKFLOW_RUNBOOK has it honored consistently regardless of
    finding type. With the default stubs (all False) and no WORKFLOW_RUNBOOK the
    answer is left at its non-destructive, no-approval defaults.
    """
    auto_trigger = _is_automatic_trigger(event_type)
    is_destructive = _is_remediation_destructive(
        standard_shortname, standard_version, standard_control
    )
    is_sensitive = _is_account_sensitive(account_id)

    approval_required = "false"
    remediation_impact = "nondestructive"

    #
    # PUT ADDITIONAL CRITERIA HERE. When done, remediation_impact and approval_required
    # must be set per your needs
    # ----------------------------------------------------------------------------------
    if auto_trigger and is_destructive and is_sensitive:
        remediation_impact = "destructive"
        approval_required = "true"

    # ----------------------------------------------------------------------------------

    # Is there an alternative workflow configured?
    alt_workflow, alt_account, alt_role = _get_alternate_workflow(account_id)

    # If so, update workflow_data
    # ---------------------------
    # When WORKFLOW_RUNBOOK is configured (and the runbook is active in the member
    # account) every remediation is redirected to it, carrying the impact/approval
    # assessment computed above. workflow_data can be modified to suit your needs.
    # Using the alt_workflow redirects the remediation to your workflow only! The
    # normal ASR workflow will not be executed.
    # ----------------------------------------------------------------------------------
    if alt_workflow:
        answer.update(
            {
                "workflowdoc": alt_workflow,
                "workflowaccount": alt_account,
                "workflowrole": alt_role,
                "workflow_data": {
                    "impact": remediation_impact,
                    "approvalrequired": approval_required,
                },
            }
        )


@tracer.capture_lambda_handler  # type: ignore[untyped-decorator]
def lambda_handler(event: Dict[str, Any], _: Any) -> StepFunctionLambdaAnswerDict:
    answer = utils.StepFunctionLambdaAnswer()
    answer.update(
        {
            "workflowdoc": "",
            "workflowaccount": "",
            "workflowrole": "",
            "workflow_data": {"impact": "nondestructive", "approvalrequired": "false"},
        }
    )
    logger.info("Processing approval requirement request", **event)
    if "Finding" not in event or "EventType" not in event:
        answer.update(
            {"status": "ERROR", "message": "Missing required data in request"}
        )
        logger.error(answer.message)
        return answer.json()

    # Multi-service findings (Inspector, GuardDuty, Macie, IAM Access Analyzer)
    # don't have a SecurityHub-style standard / control / version triple, and
    # they're not registered as non-SecurityHub products in SSM Parameter Store
    # either. Skip the standard / alt-workflow logic and return defaults — the
    # orchestrator routes them via Detail.remediationId in
    # resolve_ssm_doc_for_finding.
    if event.get("Detail", {}).get("findingType") == "multiService":
        _evaluate_approval_and_alt_workflow(
            answer,
            event_type=event["EventType"],
            standard_shortname="",
            standard_version="",
            standard_control=event.get("Detail", {}).get("remediationId", ""),
            account_id=event["Finding"].get("AwsAccountId", ""),
        )
        return answer.json()

    #
    # Check to see if this is a non-sechub finding that we are remediating
    # ----------------------------------------------------------------------------------
    product_name = (
        event["Finding"]
        .get("ProductFields", {})
        .get("aws/securityhub/ProductName", "Security Hub")
    )

    if product_name != "Security Hub":
        non_sec_hub_finding = event["Finding"]
        try:
            base_path = "/Solutions/SO0111"
            safe_product_name = extract_safe_product_name(
                non_sec_hub_finding, product_name
            )
            ssm_param = safe_ssm_path(base_path, safe_product_name)
            BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
            ssm_client = boto3.client("ssm", config=BOTO_CONFIG)
            string_workflow_args = ssm_client.get_parameter(Name=ssm_param)
            json_workflow_args = json.loads(string_workflow_args["Parameter"]["Value"])
            answer.update(
                {
                    "workflowdoc": json_workflow_args["RunbookName"],
                    "workflowrole": json_workflow_args.get("RunbookRole", ""),
                    "workflow_data": {
                        "impact": "nondestructive",
                        "approvalrequired": "false",
                        "security_hub": "false",
                    },
                }
            )
            return answer.json()
        except Exception as error:
            # Stringify so Step Functions can serialize the response — passing
            # the exception object directly produced "Runtime.MarshalError:
            # Object of type ParameterNotFound is not JSON serializable" and
            # killed the state machine.
            answer.update({"status": "ERROR", "message": str(error)})
            logger.error(answer.message)
            return answer.json()

    finding = Finding(event["Finding"])

    _evaluate_approval_and_alt_workflow(
        answer,
        event_type=event["EventType"],
        standard_shortname=finding.standard_shortname,
        standard_version=finding.standard_version,
        standard_control=finding.standard_control,
        account_id=finding.account_id,
    )

    return answer.json()
