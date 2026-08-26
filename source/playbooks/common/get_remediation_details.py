# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# NOTE: Intentionally minified to reduce CloudFormation template size.
import json
import re

import boto3


def is_wrapper(execution):
    steps = execution.get("StepExecutions", [])
    if len(steps) != 1:
        return False
    step = steps[0]
    return step.get("Action") == "aws:executeAutomation" and bool(
        re.match(r"^\d+_[\w-]+$", step.get("StepName", ""))
    )


def get_child_id(execution):
    steps = execution.get("StepExecutions", [])
    return steps[0].get("Outputs", {}).get("ExecutionId", [None])[0] if steps else None


def get_remediation_details(event, _):
    execution_id, region = event["execution_id"], event.get("target_region")
    client = boto3.client("ssm", region_name=region) if region else boto3.client("ssm")
    execution = client.get_automation_execution(AutomationExecutionId=execution_id).get(
        "AutomationExecution", {}
    )
    if is_wrapper(execution):
        child_id = get_child_id(execution)
        if child_id:
            execution = client.get_automation_execution(
                AutomationExecutionId=child_id
            ).get("AutomationExecution", {})
    return {
        "outputs": json.dumps(execution.get("Outputs", {})),
        "failure_message": execution.get("FailureMessage", ""),
    }
