# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
import pytest
from botocore.stub import Stubber
from get_remediation_details import get_remediation_details


@pytest.fixture
def ssm_client():
    return boto3.client("ssm", region_name="us-east-1")


def test_get_remediation_details_success(mocker, ssm_client):
    """
    Verifies successful retrieval of automation execution details
    """
    execution_id = "12345678-1234-1234-1234-123456789012"
    expected_outputs = {"Remediation.Output": ["Success"]}

    ssm_response = {
        "AutomationExecution": {
            "AutomationExecutionId": execution_id,
            "AutomationExecutionStatus": "Success",
            "Outputs": expected_outputs,
        }
    }

    stubber = Stubber(ssm_client)
    stubber.add_response(
        "get_automation_execution",
        ssm_response,
        {"AutomationExecutionId": execution_id},
    )
    stubber.activate()

    mocker.patch("get_remediation_details.boto3.client", return_value=ssm_client)

    event = {"execution_id": execution_id}
    result = get_remediation_details(event, None)

    assert result["outputs"] == json.dumps(expected_outputs)
    assert result["failure_message"] == ""

    stubber.deactivate()


def test_get_remediation_details_with_failure_message(mocker, ssm_client):
    """
    Verifies retrieval of failure message when automation fails
    """
    execution_id = "12345678-1234-1234-1234-123456789012"
    failure_message = "Step fails when executing script. Error: Resource not found."

    ssm_response = {
        "AutomationExecution": {
            "AutomationExecutionId": execution_id,
            "AutomationExecutionStatus": "Failed",
            "Outputs": {},
            "FailureMessage": failure_message,
        }
    }

    stubber = Stubber(ssm_client)
    stubber.add_response(
        "get_automation_execution",
        ssm_response,
        {"AutomationExecutionId": execution_id},
    )
    stubber.activate()

    mocker.patch("get_remediation_details.boto3.client", return_value=ssm_client)

    event = {"execution_id": execution_id}
    result = get_remediation_details(event, None)

    assert result["outputs"] == "{}"
    assert result["failure_message"] == failure_message

    stubber.deactivate()


def test_get_remediation_details_with_target_region(mocker, ssm_client):
    """
    Verifies that target_region is passed to boto3 client for cross-region calls
    """
    execution_id = "12345678-1234-1234-1234-123456789012"
    target_region = "eu-west-1"

    ssm_response = {
        "AutomationExecution": {
            "AutomationExecutionId": execution_id,
            "AutomationExecutionStatus": "Success",
            "Outputs": {"key": ["value"]},
        }
    }

    mock_client = mocker.patch(
        "get_remediation_details.boto3.client", return_value=ssm_client
    )

    stubber = Stubber(ssm_client)
    stubber.add_response(
        "get_automation_execution",
        ssm_response,
        {"AutomationExecutionId": execution_id},
    )
    stubber.activate()

    event = {"execution_id": execution_id, "target_region": target_region}
    get_remediation_details(event, None)

    mock_client.assert_called_once()
    call_kwargs = mock_client.call_args[1]
    assert call_kwargs["region_name"] == target_region

    stubber.deactivate()


def test_get_remediation_details_without_target_region(mocker, ssm_client):
    """
    Verifies that no region is specified when target_region is not provided
    """
    execution_id = "12345678-1234-1234-1234-123456789012"

    ssm_response = {
        "AutomationExecution": {
            "AutomationExecutionId": execution_id,
            "AutomationExecutionStatus": "Success",
            "Outputs": {},
        }
    }

    mock_client = mocker.patch(
        "get_remediation_details.boto3.client", return_value=ssm_client
    )

    stubber = Stubber(ssm_client)
    stubber.add_response(
        "get_automation_execution",
        ssm_response,
        {"AutomationExecutionId": execution_id},
    )
    stubber.activate()

    event = {"execution_id": execution_id}
    get_remediation_details(event, None)

    mock_client.assert_called_once()
    call_kwargs = mock_client.call_args[1]
    assert "region_name" not in call_kwargs

    stubber.deactivate()


def test_get_remediation_details_target_locations_wrapper(mocker, ssm_client):
    """
    Verifies that TargetLocations wrapper (dummy) executions are detected and
    the real child execution is fetched instead
    """
    wrapper_execution_id = "a9461bb9-b8e4-4fe4-a159-d19940a9f7d8"
    child_execution_id = "82f8c206-8933-4a51-bc27-84db7324d84b"
    expected_outputs = {"EnableAPIGatewayExecutionLogs.Output": ["Success"]}

    # Wrapper execution response (dummy)
    wrapper_response = {
        "AutomationExecution": {
            "AutomationExecutionId": wrapper_execution_id,
            "DocumentName": "ASR-EnableAPIGatewayExecutionLogs",
            "AutomationExecutionStatus": "Success",
            "StepExecutions": [
                {
                    "StepName": "242201278079_us-east-1",
                    "Action": "aws:executeAutomation",
                    "StepStatus": "Success",
                    "Outputs": {"ExecutionId": [child_execution_id]},
                }
            ],
            "Outputs": {},
        }
    }

    # Real child execution response
    child_response = {
        "AutomationExecution": {
            "AutomationExecutionId": child_execution_id,
            "DocumentName": "ASR-EnableAPIGatewayExecutionLogs",
            "AutomationExecutionStatus": "Success",
            "Outputs": expected_outputs,
        }
    }

    stubber = Stubber(ssm_client)
    stubber.add_response(
        "get_automation_execution",
        wrapper_response,
        {"AutomationExecutionId": wrapper_execution_id},
    )
    stubber.add_response(
        "get_automation_execution",
        child_response,
        {"AutomationExecutionId": child_execution_id},
    )
    stubber.activate()

    mocker.patch("get_remediation_details.boto3.client", return_value=ssm_client)

    event = {"execution_id": wrapper_execution_id}
    result = get_remediation_details(event, None)

    assert result["outputs"] == json.dumps(expected_outputs)
    assert result["failure_message"] == ""

    stubber.deactivate()


def test_get_remediation_details_target_locations_wrapper_failed(mocker, ssm_client):
    """
    Verifies that failure message is retrieved from the real child execution
    when TargetLocations wrapper is used and remediation fails
    """
    wrapper_execution_id = "a9461bb9-b8e4-4fe4-a159-d19940a9f7d8"
    child_execution_id = "82f8c206-8933-4a51-bc27-84db7324d84b"
    failure_message = "RuntimeError: Could not enable API Gateway execution logs."

    # Wrapper execution response (dummy)
    wrapper_response = {
        "AutomationExecution": {
            "AutomationExecutionId": wrapper_execution_id,
            "DocumentName": "ASR-EnableAPIGatewayExecutionLogs",
            "AutomationExecutionStatus": "Failed",
            "StepExecutions": [
                {
                    "StepName": "111122223333_eu-west-1",
                    "Action": "aws:executeAutomation",
                    "StepStatus": "Failed",
                    "Outputs": {"ExecutionId": [child_execution_id]},
                }
            ],
            "Outputs": {},
        }
    }

    # Real child execution response with failure
    child_response = {
        "AutomationExecution": {
            "AutomationExecutionId": child_execution_id,
            "DocumentName": "ASR-EnableAPIGatewayExecutionLogs",
            "AutomationExecutionStatus": "Failed",
            "Outputs": {},
            "FailureMessage": failure_message,
        }
    }

    stubber = Stubber(ssm_client)
    stubber.add_response(
        "get_automation_execution",
        wrapper_response,
        {"AutomationExecutionId": wrapper_execution_id},
    )
    stubber.add_response(
        "get_automation_execution",
        child_response,
        {"AutomationExecutionId": child_execution_id},
    )
    stubber.activate()

    mocker.patch("get_remediation_details.boto3.client", return_value=ssm_client)

    event = {"execution_id": wrapper_execution_id}
    result = get_remediation_details(event, None)

    assert result["outputs"] == "{}"
    assert result["failure_message"] == failure_message

    stubber.deactivate()


def test_is_not_target_locations_wrapper_multiple_steps(mocker, ssm_client):
    """
    Verifies that executions with multiple steps are NOT treated as wrappers
    """
    execution_id = "12345678-1234-1234-1234-123456789012"
    expected_outputs = {"Remediation.Output": ["Success"]}

    ssm_response = {
        "AutomationExecution": {
            "AutomationExecutionId": execution_id,
            "AutomationExecutionStatus": "Success",
            "StepExecutions": [
                {"StepName": "ParseInput", "Action": "aws:executeScript"},
                {"StepName": "Remediation", "Action": "aws:executeAutomation"},
            ],
            "Outputs": expected_outputs,
        }
    }

    stubber = Stubber(ssm_client)
    stubber.add_response(
        "get_automation_execution",
        ssm_response,
        {"AutomationExecutionId": execution_id},
    )
    stubber.activate()

    mocker.patch("get_remediation_details.boto3.client", return_value=ssm_client)

    event = {"execution_id": execution_id}
    result = get_remediation_details(event, None)

    # Should return the original execution's outputs, not try to fetch child
    assert result["outputs"] == json.dumps(expected_outputs)

    stubber.deactivate()


def test_is_not_target_locations_wrapper_different_action(mocker, ssm_client):
    """
    Verifies that single-step executions with non-executeAutomation action
    are NOT treated as wrappers
    """
    execution_id = "12345678-1234-1234-1234-123456789012"
    expected_outputs = {"Output": ["Done"]}

    ssm_response = {
        "AutomationExecution": {
            "AutomationExecutionId": execution_id,
            "AutomationExecutionStatus": "Success",
            "StepExecutions": [
                {"StepName": "111122223333_us-east-1", "Action": "aws:executeScript"},
            ],
            "Outputs": expected_outputs,
        }
    }

    stubber = Stubber(ssm_client)
    stubber.add_response(
        "get_automation_execution",
        ssm_response,
        {"AutomationExecutionId": execution_id},
    )
    stubber.activate()

    mocker.patch("get_remediation_details.boto3.client", return_value=ssm_client)

    event = {"execution_id": execution_id}
    result = get_remediation_details(event, None)

    assert result["outputs"] == json.dumps(expected_outputs)

    stubber.deactivate()


def test_is_not_target_locations_wrapper_different_step_name(mocker, ssm_client):
    """
    Verifies that single-step executeAutomation with non-matching step name
    (not account_region pattern) is NOT treated as wrapper
    """
    execution_id = "12345678-1234-1234-1234-123456789012"
    expected_outputs = {"Output": ["Done"]}

    ssm_response = {
        "AutomationExecution": {
            "AutomationExecutionId": execution_id,
            "AutomationExecutionStatus": "Success",
            "StepExecutions": [
                {"StepName": "Remediation", "Action": "aws:executeAutomation"},
            ],
            "Outputs": expected_outputs,
        }
    }

    stubber = Stubber(ssm_client)
    stubber.add_response(
        "get_automation_execution",
        ssm_response,
        {"AutomationExecutionId": execution_id},
    )
    stubber.activate()

    mocker.patch("get_remediation_details.boto3.client", return_value=ssm_client)

    event = {"execution_id": execution_id}
    result = get_remediation_details(event, None)

    assert result["outputs"] == json.dumps(expected_outputs)

    stubber.deactivate()
