# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import re
from json.decoder import JSONDecodeError
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from layer import utils
from layer.awsapi_cached_client import BotoSession
from layer.powertools_logger import get_logger
from layer.tracer_utils import init_tracer
from layer.utils import StepFunctionLambdaAnswerDict

if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient
else:
    SSMClient = object

ORCH_ROLE_NAME = "SO0111-ASR-Orchestrator-Member"  # role to use for cross-account

logger = get_logger("check_ssm_execution")
tracer = init_tracer()


def _get_ssm_client(account: str, role: str, region: str = "") -> Any:
    """
    Create a client for ssm
    """
    kwargs = {}

    if region:
        kwargs["region_name"] = region

    ssm = BotoSession(account, f"{role}").client("ssm", **kwargs)
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
            Filters=[{"Key": "ExecutionId", "Values": [self.exec_id]}]
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


def get_remediation_runbook_output(ssm_outputs: Dict[str, Any]) -> Optional[str]:
    """
    Extract the output from the child remediation runbook execution.
    This is captured by the control runbook's GetRemediationDetails step.

    SSM Automation Outputs are returned as Map<String, List<String>>, so we
    extract the first element from the list.
    """
    output_key = "GetRemediationDetails.Output"
    output_list = ssm_outputs.get(output_key, [])
    return output_list[0] if output_list else None


def get_remediation_runbook_failure_message(
    ssm_outputs: Dict[str, Any],
) -> Optional[str]:
    """
    Extract the failure message from the child remediation runbook execution.
    This is captured by the control runbook's GetRemediationDetails step.

    SSM Automation Outputs are returned as Map<String, List<String>>, so we
    extract the first element from the list.
    """
    failure_message_key = "GetRemediationDetails.FailureMessage"
    failure_message_list = ssm_outputs.get(failure_message_key, [])
    return failure_message_list[0] if failure_message_list else None


def get_backup_s3_key(ssm_outputs: Dict[str, Any]) -> str:
    """
    Extract the backup S3 object key emitted by the GuardDuty control runbook's
    ParseInput step on a successful Contain. Empty for other controls/actions.

    A later GuardDuty rollback (Restore) must pass this exact key back to
    AWSSupport-ContainIAMPrincipal, which cannot derive it. Threaded through the
    Orchestrator so send_notifications can persist it on the remediation record.
    """
    output_list = ssm_outputs.get("ParseInput.BackupS3Key", [])
    return output_list[0] if output_list else ""


def determine_remediation_output(
    remediation_runbook_output: Optional[str],
    remediation_runbook_failure_message: Optional[str],
    control_runbook_failure_message: Optional[str],
    ssm_outputs: Dict[str, Any],
    remediation_logdata: List[str],
) -> str:
    """
    Determine the appropriate remediation output based on priority:
    1. Remediation runbook failure message (highest priority)
    2. Control runbook failure message
    3. Remediation runbook output
    4. Full control runbook output
    5. Default message if none available

    Also updates remediation_logdata with the failure message if present.

    Args:
        remediation_runbook_output: Output from the remediation runbook execution
        remediation_runbook_failure_message: Failure message from remediation runbook
        control_runbook_failure_message: Failure message from control runbook
        ssm_outputs: Full SSM automation outputs from control runbook
        remediation_logdata: List to append failure messages to (modified in place)

    Returns:
        The determined remediation output string
    """
    if remediation_runbook_failure_message:
        remediation_logdata.append(remediation_runbook_failure_message)
        return remediation_runbook_failure_message
    elif control_runbook_failure_message:
        remediation_logdata.append(control_runbook_failure_message)
        return control_runbook_failure_message
    elif remediation_runbook_output:
        return remediation_runbook_output
    elif ssm_outputs:
        return json.dumps(ssm_outputs)
    else:
        return (
            "No output available - check the Step Function execution logs for details."
        )


@tracer.capture_lambda_handler  # type: ignore[untyped-decorator]
def lambda_handler(event: Dict[str, Any], _: Any) -> StepFunctionLambdaAnswerDict:
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
        logger.error(answer.message)
        return answer.json()

    SSM_EXEC_ID = event["SSMExecution"]["SSMExecutionId"]
    SSM_ACCOUNT = event["SSMExecution"].get("Account")
    SSM_REGION = event["SSMExecution"].get("Region")

    if not all([SSM_ACCOUNT, SSM_REGION]):
        exit(
            "ERROR: missing remediation account information. SSMExecution missing region or account."
        )

    try:
        automation_exec_info = AutomationExecution(
            SSM_EXEC_ID, SSM_ACCOUNT, ORCH_ROLE_NAME, SSM_REGION
        )
    except Exception as e:
        logger.error(f"Unable to retrieve AutomationExecution data: {str(e)}")
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

        remediation_logdata = get_execution_log(remediation_response)

        if automation_exec_info.failure_message:
            remediation_logdata.append(automation_exec_info.failure_message)

        # Extract output and failure message from child remediation runbook
        remediation_runbook_output = get_remediation_runbook_output(ssm_outputs)
        remediation_runbook_failure_message = get_remediation_runbook_failure_message(
            ssm_outputs
        )

        remediation_output = determine_remediation_output(
            remediation_runbook_output=remediation_runbook_output,
            remediation_runbook_failure_message=remediation_runbook_failure_message,
            control_runbook_failure_message=automation_exec_info.failure_message,
            ssm_outputs=ssm_outputs,
            remediation_logdata=remediation_logdata,
        )

        answer.update(
            {
                "status": automation_exec_info.status,
                "remediation_status": status_for_message,
                "message": remediation_message,
                "remediation_output": remediation_output,
                "executionid": SSM_EXEC_ID,
                "affected_object": affected_object,
                "backup_s3_key": get_backup_s3_key(ssm_outputs),
                "logdata": json.dumps(remediation_logdata, default=str),
            }
        )
    else:
        answer.update(
            {
                "status": automation_exec_info.status,
                "remediation_status": "running",
                "message": "Waiting for completion",
                "remediation_output": "",
                "executionid": SSM_EXEC_ID,
                "affected_object": "",
                "backup_s3_key": "",
                "logdata": [],
            }
        )

    return answer.json()
