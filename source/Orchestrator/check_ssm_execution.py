# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import re
from json.decoder import JSONDecodeError
from typing import TYPE_CHECKING, Any, Optional

from layer import tracer_utils, utils
from layer.awsapi_cached_client import BotoSession
from layer.logger import Logger
from layer.metrics import Metrics

if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient
else:
    SSMClient = object

ORCH_ROLE_NAME = "SO0111-SHARR-Orchestrator-Member"  # role to use for cross-account

# initialise loggers
LOG_LEVEL = os.getenv("log_level", "info")
LOGGER = Logger(loglevel=LOG_LEVEL)

tracer = tracer_utils.init_tracer()


def _get_ssm_client(account: str, role: str, region: str = "") -> SSMClient:
    """
    Create a client for ssm
    """
    kwargs = {}

    if region:
        kwargs["region_name"] = region

    ssm: SSMClient = BotoSession(account, f"{role}").client("ssm", **kwargs)
    return ssm


class ParameterError(Exception):
    error = "Invalid parameter input"

    def __init__(self, error=""):
        if error:
            self.error = error
        super().__init__(self.error)

    def __str__(self):
        return f"{self.error}"


class AutomationExecution(object):
    status = None
    outputs: Any = {}
    failure_message = None
    exec_id: Optional[str] = None
    account = None
    role_base_name = None
    region = None  # Region where the ssm doc is running

    def __init__(self, exec_id, account, role_base_name, region):
        if not re.match(
            "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", exec_id
        ):
            raise ParameterError(f"Invalid Automation Execution Id: {exec_id}")
        self.exec_id = exec_id
        if not re.match(r"^\d{12}$", account):
            raise ParameterError(f"Invalid Value for Account: {account}")
        self.account = account
        if not re.match(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$", region):
            raise ParameterError(f"Invalid Value for Region: {region}")
        self.region = region
        if not re.match("^[a-zA-Z0-9_+=,.@-]{1,64}$", role_base_name):
            raise ParameterError(f"Invalid Value for Role_Base_Name: {role_base_name}")

        self._ssm_client = _get_ssm_client(self.account, role_base_name, self.region)
        self.get_execution_state()

    def get_execution_state(self):
        automation_exec_info = self._ssm_client.describe_automation_executions(
            Filters=[{"Key": "ExecutionId", "Values": [self.exec_id]}]  # type: ignore[list-item]
        )

        self.status = automation_exec_info["AutomationExecutionMetadataList"][0].get(
            "AutomationExecutionStatus", "ERROR"
        )

        self.outputs = automation_exec_info["AutomationExecutionMetadataList"][0].get(
            "Outputs", {}
        )

        remediation_output_name = "Remediation.Output"
        if (
            remediation_output_name in self.outputs
            and isinstance(self.outputs[remediation_output_name], list)
            and len(self.outputs[remediation_output_name]) == 1
            and self.outputs[remediation_output_name][0]
            == "No output available yet because the step is not successfully executed"
        ):
            self.outputs[remediation_output_name][
                0
            ] = "See Automation Execution output for details"

        self.failure_message = automation_exec_info["AutomationExecutionMetadataList"][
            0
        ].get("FailureMessage", "")


def valid_automation_doc(automation_doc):
    return (
        "SecurityStandard" in automation_doc
        and "ControlId" in automation_doc
        and "AccountId" in automation_doc
    )


def get_execution_log(response_data):
    logdata = []
    if "ExecutionLog" in response_data:
        logdata = response_data["ExecutionLog"].split("\n")

    return logdata


def get_affected_object(response_data):
    affected_object_out = "UNKNOWN"
    if "ParseInput.AffectedObject" in response_data:
        affected_object = response_data.get("ParseInput.AffectedObject")[0]
        try:
            affected_object = json.loads(affected_object)
            if "Type" in affected_object and "Id" in affected_object:
                affected_object_out = (
                    affected_object["Type"] + " " + affected_object["Id"]
                )
            else:
                affected_object_out = str(affected_object)
        except JSONDecodeError:
            print("Expected serialized json, got " + str(affected_object))
            affected_object_out = str(affected_object)

    return affected_object_out


def get_remediation_status(response_data, exec_status):
    status = exec_status
    if "Payload" in response_data and "response" in response_data["Payload"]:
        status = response_data["Payload"]["response"].get("status", "UNKNOWN")
    elif "status" in response_data:
        status = response_data["status"]
    return status


def get_remediation_message(response_data, remediation_status):
    message = f"Remediation status: {remediation_status} - please verify remediation"
    message_key = next((key for key in response_data if key.lower() == "message"), None)
    if "Payload" in response_data and "response" in response_data["Payload"]:
        message = response_data["Payload"]["response"].get("status", "UNKNOWN")
    elif message_key:
        message = response_data[message_key]
    return message


def get_remediation_output(response_data: dict[str, str]) -> str:
    message_key = next((key for key in response_data if key.lower() == "message"), "")
    if message_key:
        response_data.pop(
            message_key, ""
        )  # Delete 'message' if it is present, since it will be included in the remediation message
    return str(response_data)


def get_remediation_response(remediation_response_raw):
    remediation_response = {}
    if isinstance(remediation_response_raw, list):
        try:
            remediation_response = json.loads(remediation_response_raw[0])
        except JSONDecodeError:
            remediation_response = {"message": remediation_response_raw[0]}
        except Exception as e:
            print(e)
            print("Unhandled error")
    elif isinstance(remediation_response_raw, str):
        remediation_response = {"message": remediation_response_raw}
    elif isinstance(remediation_response_raw, dict):
        remediation_response = remediation_response_raw
    return remediation_response


@tracer.capture_lambda_handler
def lambda_handler(event, _):
    answer = utils.StepFunctionLambdaAnswer()
    automation_doc = event["AutomationDocument"]

    if not valid_automation_doc(automation_doc):
        answer.update(
            {
                "status": "ERROR",
                "message": "Missing AutomationDocument data in request: "
                + json.dumps(automation_doc),
            }
        )
        LOGGER.error(answer.message)
        return answer.json()

    SSM_EXEC_ID = event["SSMExecution"]["ExecId"]
    SSM_ACCOUNT = event["SSMExecution"].get("Account")
    SSM_REGION = event["SSMExecution"].get("Region")

    if not all([SSM_ACCOUNT, SSM_REGION]):
        exit(
            "ERROR: missing remediation account information. SSMExecution missing region or account."
        )

    metrics_obj = Metrics(event["EventType"])
    metrics_data = metrics_obj.get_metrics_from_event(event)

    try:
        automation_exec_info = AutomationExecution(
            SSM_EXEC_ID, SSM_ACCOUNT, ORCH_ROLE_NAME, SSM_REGION
        )
    except Exception as e:
        LOGGER.error(f"Unable to retrieve AutomationExecution data: {str(e)}")
        raise e

    # Terminal states - get log data from AutomationExecutionMetadataList
    #
    # AutomationExecutionStatus - was the ssm doc successful? (did it not blow up)
    # Outputs -
    #   ParseInput.AffectedObject - what was the finding asserted on? Can be a string value or a dict
    #       Ex. 111111111111 - AWS AccountId
    #       Ex { 'Type': string, 'Id': string }
    #   VerifyRemediation.Output or Remediation.Output - what the script, if any, returned
    #       ExecutionLog: stdout from the script, added automatically when there is a return statement
    #       response: returned by the script itself.
    #           status: [SUCCESS|FAILED] - did the REMEDIATION succeed?
    #   VerifyRemediation.Output or Remediation.Output may be a string, when using a child runbook for
    #       remediation.

    if automation_exec_info.status in (
        "Success",
        "TimedOut",
        "Cancelled",
        "Cancelling",
        "Failed",
    ):
        ssm_outputs = automation_exec_info.outputs
        affected_object = get_affected_object(ssm_outputs)
        remediation_response_raw = None
        remediation_output_name = "Remediation.Output"

        if remediation_output_name in ssm_outputs:
            remediation_response_raw = ssm_outputs[remediation_output_name]
        elif "VerifyRemediation.Output" in ssm_outputs:
            remediation_response_raw = ssm_outputs["VerifyRemediation.Output"]
        else:
            remediation_response_raw = json.dumps(ssm_outputs)

        remediation_response = get_remediation_response(remediation_response_raw)

        status_for_message = automation_exec_info.status
        if automation_exec_info.status == "Success":
            remediation_status = get_remediation_status(
                remediation_response, automation_exec_info.status
            )
            status_for_message = remediation_status
            print(f"Remediation Status: {remediation_status}")

        remediation_message = get_remediation_message(
            remediation_response, status_for_message
        )

        remediation_output = get_remediation_output(remediation_response)

        remediation_logdata = get_execution_log(remediation_response)

        # FailureMessage is only set when the remediation was another SSM doc, not
        if automation_exec_info.failure_message:
            remediation_logdata.append(automation_exec_info.failure_message)

        answer.update(
            {
                "status": automation_exec_info.status,
                "remediation_status": status_for_message,
                "message": remediation_message,
                "remediation_output": remediation_output,
                "executionid": SSM_EXEC_ID,
                "affected_object": affected_object,
                "logdata": json.dumps(remediation_logdata, default=str),
            }
        )

        try:
            metrics_data["status"] = status_for_message
            metrics_obj.send_metrics(metrics_data)
        except Exception as e:
            LOGGER.error(e)
            LOGGER.error("Failed to send metrics")

    else:
        answer.update(
            {
                "status": automation_exec_info.status,
                "remediation_status": "running",
                "message": "Waiting for completion",
                "remediation_output": "",
                "executionid": SSM_EXEC_ID,
                "affected_object": "",
                "logdata": [],
            }
        )

    return answer.json()
