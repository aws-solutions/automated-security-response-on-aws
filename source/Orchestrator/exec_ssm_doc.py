# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import re

from botocore.exceptions import ClientError
from layer import utils
from layer.awsapi_cached_client import BotoSession
from layer.logger import Logger

AWS_PARTITION = os.getenv("AWS_PARTITION")
AWS_REGION = os.getenv("AWS_REGION")
SOLUTION_ID = os.getenv("SOLUTION_ID", "SO0111")
SOLUTION_ID = re.sub(r"^DEV-", "", SOLUTION_ID)

# initialise loggers
LOG_LEVEL = os.getenv("log_level", "info")
LOGGER = Logger(loglevel=LOG_LEVEL)


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


def lambda_role_exists(account, rolename):
    iam = _get_iam_client(account, SOLUTION_ID + "-SHARR-Orchestrator-Member")
    try:
        iam.get_role(RoleName=rolename)
        return True
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        if exception_type in "NoSuchEntity":
            return False
        else:
            exit("An unhandled client error occurred: " + exception_type)
    except Exception as e:
        exit("An unhandled error occurred: " + str(e))


def lambda_handler(event, _):
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
    LOGGER.info(event)
    if "Finding" not in event or "EventType" not in event:
        answer.update(
            {"status": "ERROR", "message": "Missing required data in request"}
        )
        LOGGER.error(answer.message)
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
        LOGGER.error(answer.message)
        return answer.json()

    # Execution role will be, in order of precedence
    # 1) remote_workflow_role
    # 2) Derived from standard and control if it exists
    # 3) Orchestrator Member role
    #
    # In most cases the Orchestrator Member role is used, and it passes
    # the value in RemediationRole as the AutomationExectutionRole
    remediation_role = SOLUTION_ID + "-SHARR-Orchestrator-Member"  # default
    if alt_workflow_doc and alt_workflow_role:
        remediation_role = alt_workflow_role
    elif lambda_role_exists(execution_account, automation_doc["RemediationRole"]):
        remediation_role = automation_doc["RemediationRole"]

    print(
        f"Using role {remediation_role} to execute {remote_workflow_doc} in {execution_account}  {execution_region}"
    )

    remediation_role_arn = (
        f"arn:{AWS_PARTITION}:iam::{execution_account}:role/{remediation_role}"
    )
    print(f"ARN: {remediation_role_arn}")

    ssm = _get_ssm_client(execution_account, remediation_role, execution_region)

    ssm_parameters = {
        "Finding": [json.dumps(event["Finding"])],
        "AutomationAssumeRole": [remediation_role_arn],
    }
    if remote_workflow_doc != automation_doc["AutomationDocId"]:
        ssm_parameters["RemediationDoc"] = [automation_doc["AutomationDocId"]]
        ssm_parameters["Workflow"] = [json.dumps(event.get("Workflow", {}))]

    # Check if this a security hub finding, if not then we only send the finding.
    workflow_data = event.get("Workflow", {}).get("WorkflowConfig", {})

    if "security_hub" in workflow_data:
        if workflow_data["security_hub"] == "false":
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
            "executionregion": execution_region,
            "executionaccount": execution_account,
        }
    )

    LOGGER.info(answer.message)

    return answer.json()
